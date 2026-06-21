const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const nodemailer = require('nodemailer');
const path       = require('path');
const db         = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'glazed-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (req.session.admin) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── Email ─────────────────────────────────────────────────────────────────────

function getSettings() {
  return Object.fromEntries(
    db.prepare('SELECT key, value FROM settings').all().map(r => [r.key, r.value])
  );
}

async function sendEmail(subject, html) {
  const s = getSettings();
  if (!s.smtp_host || !s.smtp_user || !s.smtp_pass) return false;

  const transporter = nodemailer.createTransport({
    host: s.smtp_host,
    port: Number(s.smtp_port) || 587,
    secure: Number(s.smtp_port) === 465,
    auth: { user: s.smtp_user, pass: s.smtp_pass }
  });

  await transporter.sendMail({
    from: s.smtp_from || s.smtp_user,
    to: s.notify_email,
    subject,
    html
  });
  return true;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const admin = db.prepare('SELECT * FROM admin WHERE username = ?').get(username);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.admin = { id: admin.id, username: admin.username };
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ admin: req.session.admin || null });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const admin = db.prepare('SELECT * FROM admin WHERE id = ?').get(req.session.admin.id);
  if (!bcrypt.compareSync(currentPassword, admin.password_hash))
    return res.status(400).json({ error: 'Current password is incorrect' });
  db.prepare('UPDATE admin SET password_hash = ? WHERE id = ?')
    .run(bcrypt.hashSync(newPassword, 10), req.session.admin.id);
  res.json({ ok: true });
});

// ── Settings ──────────────────────────────────────────────────────────────────

app.get('/api/settings', requireAuth, (req, res) => {
  const s = getSettings();
  res.json({ ...s, smtp_pass: s.smtp_pass ? '••••••••' : '' });
});

app.put('/api/settings', requireAuth, (req, res) => {
  const allowed = ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_from', 'notify_email'];
  const upsert  = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  db.transaction(() => {
    for (const key of allowed) {
      if (!(key in req.body)) continue;
      if (key === 'smtp_pass' && req.body[key] === '••••••••') continue;
      upsert.run(key, req.body[key]);
    }
  })();
  res.json({ ok: true });
});

app.post('/api/test-email', requireAuth, async (req, res) => {
  try {
    const sent = await sendEmail(
      '🍩 Test Email — Glazed & Amazed',
      '<h2 style="color:#f7567c">It works!</h2><p>Your email notifications are configured correctly.</p>'
    );
    if (!sent) return res.status(400).json({ error: 'SMTP is not configured yet' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Donuts (public read) ──────────────────────────────────────────────────────

app.get('/api/donuts', (req, res) => {
  res.json(db.prepare('SELECT * FROM donuts ORDER BY id').all());
});

// ── Donuts (admin write) ──────────────────────────────────────────────────────

app.post('/api/donuts', requireAuth, (req, res) => {
  const { name, description, price, emoji, quantity, low_stock_threshold } = req.body;
  if (!name || price == null) return res.status(400).json({ error: 'name and price are required' });
  const result = db.prepare(
    'INSERT INTO donuts (name, description, price, emoji, quantity, low_stock_threshold) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(name, description || '', Number(price), emoji || '🍩', Number(quantity) || 0, Number(low_stock_threshold) || 5);
  res.status(201).json(db.prepare('SELECT * FROM donuts WHERE id = ?').get(result.lastInsertRowid));
});

app.put('/api/donuts/:id', requireAuth, (req, res) => {
  const { name, description, price, emoji, available, quantity, low_stock_threshold } = req.body;
  if (!name || price == null) return res.status(400).json({ error: 'name and price are required' });
  const changes = db.prepare(
    'UPDATE donuts SET name=?, description=?, price=?, emoji=?, available=?, quantity=?, low_stock_threshold=? WHERE id=?'
  ).run(
    name, description || '', Number(price), emoji || '🍩',
    available ? 1 : 0,
    Number(quantity) || 0,
    Number(low_stock_threshold) || 5,
    req.params.id
  ).changes;
  if (!changes) return res.status(404).json({ error: 'Not found' });
  res.json(db.prepare('SELECT * FROM donuts WHERE id = ?').get(req.params.id));
});

app.delete('/api/donuts/:id', requireAuth, (req, res) => {
  const changes = db.prepare('DELETE FROM donuts WHERE id = ?').run(req.params.id).changes;
  if (!changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Orders (public) ───────────────────────────────────────────────────────────

app.post('/api/orders', async (req, res) => {
  const { items, customerName, customerEmail, notes } = req.body;

  if (!customerName) return res.status(400).json({ error: 'Your name is required' });
  if (!items || !items.length) return res.status(400).json({ error: 'No items selected' });

  // Validate stock
  const orderItems = [];
  for (const { donutId, quantity } of items) {
    const qty = Number(quantity);
    if (!qty || qty < 1) continue;
    const donut = db.prepare('SELECT * FROM donuts WHERE id = ? AND available = 1').get(donutId);
    if (!donut) return res.status(400).json({ error: `Item not found` });
    if (donut.quantity < qty)
      return res.status(400).json({ error: `Only ${donut.quantity} left of "${donut.name}"` });
    orderItems.push({ donut, quantity: qty });
  }

  if (!orderItems.length) return res.status(400).json({ error: 'No valid items in order' });

  // Deduct stock atomically; auto-mark unavailable when quantity hits 0
  db.transaction(() => {
    for (const { donut, quantity } of orderItems) {
      const newQty = donut.quantity - quantity;
      db.prepare('UPDATE donuts SET quantity = ?, available = ? WHERE id = ?')
        .run(newQty, newQty > 0 ? 1 : 0, donut.id);
    }
  })();

  const total = orderItems.reduce((s, { donut, quantity }) => s + donut.price * quantity, 0);

  // Fire-and-forget emails
  const itemRows = orderItems
    .map(({ donut, quantity }) =>
      `<tr><td>${donut.emoji} ${donut.name}</td><td>×${quantity}</td><td>$${(donut.price * quantity).toFixed(2)}</td></tr>`)
    .join('');

  sendEmail(
    `🍩 New Order from ${customerName}`,
    `<h2 style="color:#f7567c">New Order Received</h2>
     <p><b>Customer:</b> ${customerName}${customerEmail ? ` &lt;${customerEmail}&gt;` : ''}</p>
     <table border="0" cellpadding="6" style="border-collapse:collapse;width:100%">
       <thead><tr style="background:#fff3e0"><th align="left">Item</th><th>Qty</th><th>Price</th></tr></thead>
       <tbody>${itemRows}</tbody>
       <tfoot><tr><td colspan="2"><b>Total</b></td><td><b>$${total.toFixed(2)}</b></td></tr></tfoot>
     </table>
     ${notes ? `<p><b>Notes:</b> ${notes}</p>` : ''}
    `
  ).catch(() => {});

  // Check for newly low stock after deduction
  const lowItems = orderItems
    .map(({ donut }) => db.prepare('SELECT * FROM donuts WHERE id = ?').get(donut.id))
    .filter(d => d.quantity <= d.low_stock_threshold);

  if (lowItems.length) {
    const rows = lowItems
      .map(d => `<li>${d.emoji} <b>${d.name}</b>: ${d.quantity} remaining (threshold: ${d.low_stock_threshold})</li>`)
      .join('');
    sendEmail(
      `⚠️ Low Stock Alert — ${lowItems.length} item${lowItems.length > 1 ? 's' : ''} running low`,
      `<h2 style="color:#f7567c">Low Stock Alert</h2>
       <p>The following donuts dropped below their restock threshold after a recent order:</p>
       <ul>${rows}</ul>
       <p><a href="http://localhost:${PORT}/admin.html">Log in to restock →</a></p>`
    ).catch(() => {});
  }

  res.json({
    ok: true,
    total,
    items: orderItems.map(({ donut, quantity }) => ({ name: donut.name, emoji: donut.emoji, quantity, price: donut.price }))
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🍩 Glazed & Amazed running at http://localhost:${PORT}`);
  console.log(`🔐 Admin portal: http://localhost:${PORT}/admin.html`);
  console.log(`   Default login: admin / donuts123\n`);
});
