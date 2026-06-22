const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const path       = require('path');
const { db, init } = require('./db');

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

// ── Helpers ───────────────────────────────────────────────────────────────────

async function getSettings() {
  const rows = await db.execute('SELECT key, value FROM settings');
  return Object.fromEntries(rows.rows.map(r => [r.key, r.value]));
}

async function sendEmail(subject, html, to) {
  const s = await getSettings();
  if (!s.brevo_key || !s.notify_email) return false;
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': s.brevo_key, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sender:      { name: 'Glazed & Amazed', email: s.smtp_from || s.smtp_user || 'noreply@glazedandamazed.com' },
      to:          [{ email: to || s.notify_email }],
      subject,
      htmlContent: html,
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Brevo error: ${err}`);
  }
  return true;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await db.execute({ sql: 'SELECT * FROM admin WHERE username = ?', args: [username] });
    const admin = result.rows[0];
    if (!admin || !bcrypt.compareSync(password, admin.password_hash))
      return res.status(401).json({ error: 'Invalid credentials' });
    req.session.admin = { id: Number(admin.id), username: admin.username };
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ admin: req.session.admin || null });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const result = await db.execute({ sql: 'SELECT * FROM admin WHERE id = ?', args: [req.session.admin.id] });
    const admin = result.rows[0];
    if (!bcrypt.compareSync(currentPassword, admin.password_hash))
      return res.status(400).json({ error: 'Current password is incorrect' });
    await db.execute({ sql: 'UPDATE admin SET password_hash = ? WHERE id = ?', args: [bcrypt.hashSync(newPassword, 10), req.session.admin.id] });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Settings ──────────────────────────────────────────────────────────────────

app.get('/api/settings', requireAuth, async (req, res) => {
  try {
    const s = await getSettings();
    res.json({ ...s, brevo_key: s.brevo_key ? '••••••••' : '' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/settings', requireAuth, async (req, res) => {
  try {
    const allowed = ['brevo_key', 'smtp_from', 'smtp_user', 'notify_email', 'order_confirm_subject', 'order_confirm_body'];
    for (const key of allowed) {
      if (!(key in req.body)) continue;
      if (key === 'brevo_key' && req.body[key] === '••••••••') continue;
      await db.execute({ sql: 'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', args: [key, req.body[key]] });
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/test-email', requireAuth, async (req, res) => {
  try {
    const sent = await sendEmail(
      '🍩 Test Email — Glazed & Amazed',
      '<h2 style="color:#f7567c">It works!</h2><p>Your email notifications are configured correctly.</p>'
    );
    if (!sent) return res.status(400).json({ error: 'SMTP is not configured yet' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Donuts (public) ───────────────────────────────────────────────────────────

app.get('/api/donuts', async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM donuts ORDER BY id');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Donuts (admin write) ──────────────────────────────────────────────────────

app.post('/api/donuts', requireAuth, async (req, res) => {
  try {
    const { name, description, price, emoji, quantity, low_stock_threshold } = req.body;
    if (!name || price == null) return res.status(400).json({ error: 'name and price are required' });
    const result = await db.execute({
      sql:  'INSERT INTO donuts (name, description, price, emoji, quantity, low_stock_threshold) VALUES (?, ?, ?, ?, ?, ?)',
      args: [name, description || '', Number(price), emoji || '🍩', Number(quantity) || 0, Number(low_stock_threshold) || 5],
    });
    const row = await db.execute({ sql: 'SELECT * FROM donuts WHERE id = ?', args: [result.lastInsertRowid] });
    res.status(201).json(row.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/donuts/:id', requireAuth, async (req, res) => {
  try {
    const { name, description, price, emoji, available, quantity, low_stock_threshold } = req.body;
    if (!name || price == null) return res.status(400).json({ error: 'name and price are required' });
    const result = await db.execute({
      sql:  'UPDATE donuts SET name=?, description=?, price=?, emoji=?, available=?, quantity=?, low_stock_threshold=? WHERE id=?',
      args: [name, description || '', Number(price), emoji || '🍩', available ? 1 : 0, Number(quantity) || 0, Number(low_stock_threshold) || 5, req.params.id],
    });
    if (!result.rowsAffected) return res.status(404).json({ error: 'Not found' });
    const row = await db.execute({ sql: 'SELECT * FROM donuts WHERE id = ?', args: [req.params.id] });
    res.json(row.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/donuts/:id', requireAuth, async (req, res) => {
  try {
    const result = await db.execute({ sql: 'DELETE FROM donuts WHERE id = ?', args: [req.params.id] });
    if (!result.rowsAffected) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Orders (public) ───────────────────────────────────────────────────────────

app.post('/api/orders', async (req, res) => {
  try {
    const { items, customerName, customerEmail, notes } = req.body;
    if (!customerName)  return res.status(400).json({ error: 'Your name is required' });
    if (!customerEmail) return res.status(400).json({ error: 'Your email is required' });
    if (!items || !items.length) return res.status(400).json({ error: 'No items selected' });

    const orderItems = [];
    for (const { donutId, quantity } of items) {
      const qty = Number(quantity);
      if (!qty || qty < 1) continue;
      const r = await db.execute({ sql: 'SELECT * FROM donuts WHERE id = ? AND available = 1', args: [donutId] });
      const donut = r.rows[0];
      if (!donut) return res.status(400).json({ error: 'Item not found' });
      if (donut.quantity < qty)
        return res.status(400).json({ error: `Only ${donut.quantity} left of "${donut.name}"` });
      orderItems.push({ donut, quantity: qty });
    }

    if (!orderItems.length) return res.status(400).json({ error: 'No valid items in order' });

    for (const { donut, quantity } of orderItems) {
      const newQty = Number(donut.quantity) - quantity;
      await db.execute({
        sql:  'UPDATE donuts SET quantity = ?, available = ? WHERE id = ?',
        args: [newQty, newQty > 0 ? 1 : 0, donut.id],
      });
    }

    const total = orderItems.reduce((s, { donut, quantity }) => s + Number(donut.price) * quantity, 0);

    await db.execute({
      sql:  'INSERT INTO orders (type, customer_name, customer_email, notes, items_json, total, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      args: ['donut', customerName, customerEmail, notes || '', JSON.stringify(orderItems.map(({ donut, quantity }) => ({ name: donut.name, emoji: donut.emoji, quantity, price: Number(donut.price) }))), total, 'pending', new Date().toISOString()],
    });

    const itemRows = orderItems
      .map(({ donut, quantity }) =>
        `<tr><td>${donut.emoji} ${donut.name}</td><td>×${quantity}</td><td>$${(Number(donut.price) * quantity).toFixed(2)}</td></tr>`)
      .join('');

    const orderTable = `
      <table border="0" cellpadding="6" style="border-collapse:collapse;width:100%;font-family:sans-serif">
        <thead><tr style="background:#fff3e0"><th align="left">Item</th><th>Qty</th><th>Price</th></tr></thead>
        <tbody>${itemRows}</tbody>
        <tfoot><tr><td colspan="2"><b>Total</b></td><td><b>$${total.toFixed(2)}</b></td></tr></tfoot>
      </table>`;

    // Notify the shop owner
    sendEmail(
      `🍩 New Order from ${customerName}`,
      `<h2 style="color:#f7567c">New Order Received</h2>
       <p><b>Customer:</b> ${customerName} &lt;${customerEmail}&gt;</p>
       ${orderTable}
       ${notes ? `<p><b>Notes:</b> ${notes}</p>` : ''}`
    ).catch(() => {});

    // Send confirmation to the customer (template editable in admin Email Settings)
    const s = await getSettings();
    const notesHtml = notes ? `<p><b>Your notes:</b> ${notes}</p>` : '';
    const confirmSubject = (s.order_confirm_subject || `Your Glazed & Amazed order is confirmed! 🍩`)
      .replace(/\{\{customerName\}\}/g, customerName)
      .replace(/\{\{total\}\}/g, `$${total.toFixed(2)}`);
    const confirmBody = s.order_confirm_body
      ? s.order_confirm_body
          .replace(/\{\{customerName\}\}/g, customerName)
          .replace(/\{\{orderTable\}\}/g, orderTable)
          .replace(/\{\{notes\}\}/g, notesHtml)
          .replace(/\{\{total\}\}/g, `$${total.toFixed(2)}`)
      : `<div style="font-family:sans-serif;max-width:520px;margin:auto"><h2 style="color:#f7567c">Thanks for your order, ${customerName}!</h2><p>We're getting your donuts ready. Here's what you ordered:</p>${orderTable}${notesHtml}<p style="margin-top:1.5rem;color:#7a5230">📍 123 Sprinkle Lane, Bakerville, CA 90210<br>📞 (555) 867-5309</p><p style="color:#aaa;font-size:.85rem">Glazed &amp; Amazed — Made fresh daily.</p></div>`;
    sendEmail(confirmSubject, confirmBody, customerEmail).catch(() => {});

    // Low stock alerts
    for (const { donut } of orderItems) {
      const r = await db.execute({ sql: 'SELECT * FROM donuts WHERE id = ?', args: [donut.id] });
      const updated = r.rows[0];
      if (Number(updated.quantity) <= Number(updated.low_stock_threshold)) {
        sendEmail(
          `⚠️ Low Stock Alert — ${updated.name}`,
          `<h2 style="color:#f7567c">Low Stock Alert</h2>
           <ul><li>${updated.emoji} <b>${updated.name}</b>: ${updated.quantity} remaining (threshold: ${updated.low_stock_threshold})</li></ul>`
        ).catch(() => {});
      }
    }

    res.json({
      ok: true,
      total,
      items: orderItems.map(({ donut, quantity }) => ({ name: donut.name, emoji: donut.emoji, quantity, price: Number(donut.price) }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Food Items (public) ───────────────────────────────────────────────────────

app.get('/api/food-items', async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM food_items ORDER BY id');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Food Items (admin write) ──────────────────────────────────────────────────

app.post('/api/food-items', requireAuth, async (req, res) => {
  try {
    const { name, description, price, emoji, quantity, low_stock_threshold } = req.body;
    if (!name || price == null) return res.status(400).json({ error: 'name and price are required' });
    const result = await db.execute({
      sql:  'INSERT INTO food_items (name, description, price, emoji, quantity, low_stock_threshold) VALUES (?, ?, ?, ?, ?, ?)',
      args: [name, description || '', Number(price), emoji || '🍽️', Number(quantity) || 0, Number(low_stock_threshold) || 5],
    });
    const row = await db.execute({ sql: 'SELECT * FROM food_items WHERE id = ?', args: [result.lastInsertRowid] });
    res.status(201).json(row.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/food-items/:id', requireAuth, async (req, res) => {
  try {
    const { name, description, price, emoji, available, quantity, low_stock_threshold } = req.body;
    if (!name || price == null) return res.status(400).json({ error: 'name and price are required' });
    const result = await db.execute({
      sql:  'UPDATE food_items SET name=?, description=?, price=?, emoji=?, available=?, quantity=?, low_stock_threshold=? WHERE id=?',
      args: [name, description || '', Number(price), emoji || '🍽️', available ? 1 : 0, Number(quantity) || 0, Number(low_stock_threshold) || 5, req.params.id],
    });
    if (!result.rowsAffected) return res.status(404).json({ error: 'Not found' });
    const row = await db.execute({ sql: 'SELECT * FROM food_items WHERE id = ?', args: [req.params.id] });
    res.json(row.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/food-items/:id', requireAuth, async (req, res) => {
  try {
    const result = await db.execute({ sql: 'DELETE FROM food_items WHERE id = ?', args: [req.params.id] });
    if (!result.rowsAffected) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Food Orders (public) ──────────────────────────────────────────────────────

app.post('/api/food-orders', async (req, res) => {
  try {
    const { items, customerName, customerEmail, notes } = req.body;
    if (!customerName)  return res.status(400).json({ error: 'Your name is required' });
    if (!customerEmail) return res.status(400).json({ error: 'Your email is required' });
    if (!items || !items.length) return res.status(400).json({ error: 'No items selected' });

    const orderItems = [];
    for (const { itemId, quantity } of items) {
      const qty = Number(quantity);
      if (!qty || qty < 1) continue;
      const r = await db.execute({ sql: 'SELECT * FROM food_items WHERE id = ? AND available = 1', args: [itemId] });
      const item = r.rows[0];
      if (!item) return res.status(400).json({ error: 'Item not found' });
      if (item.quantity < qty)
        return res.status(400).json({ error: `Only ${item.quantity} left of "${item.name}"` });
      orderItems.push({ item, quantity: qty });
    }

    if (!orderItems.length) return res.status(400).json({ error: 'No valid items in order' });

    for (const { item, quantity } of orderItems) {
      const newQty = Number(item.quantity) - quantity;
      await db.execute({
        sql:  'UPDATE food_items SET quantity = ?, available = ? WHERE id = ?',
        args: [newQty, newQty > 0 ? 1 : 0, item.id],
      });
    }

    const total = orderItems.reduce((s, { item, quantity }) => s + Number(item.price) * quantity, 0);

    await db.execute({
      sql:  'INSERT INTO orders (type, customer_name, customer_email, notes, items_json, total, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      args: ['food', customerName, customerEmail, notes || '', JSON.stringify(orderItems.map(({ item, quantity }) => ({ name: item.name, emoji: item.emoji, quantity, price: Number(item.price) }))), total, 'pending', new Date().toISOString()],
    });

    const itemRows = orderItems
      .map(({ item, quantity }) =>
        `<tr><td>${item.emoji} ${item.name}</td><td>×${quantity}</td><td>$${(Number(item.price) * quantity).toFixed(2)}</td></tr>`)
      .join('');

    const orderTable = `
      <table border="0" cellpadding="6" style="border-collapse:collapse;width:100%;font-family:sans-serif">
        <thead><tr style="background:#d8f3dc"><th align="left">Item</th><th>Qty</th><th>Price</th></tr></thead>
        <tbody>${itemRows}</tbody>
        <tfoot><tr><td colspan="2"><b>Total</b></td><td><b>$${total.toFixed(2)}</b></td></tr></tfoot>
      </table>`;

    sendEmail(
      `🥘 New Sranan Kitchen Order from ${customerName}`,
      `<h2 style="color:#2d6a4f">New Order — Sranan Kitchen</h2>
       <p><b>Customer:</b> ${customerName} &lt;${customerEmail}&gt;</p>
       ${orderTable}
       ${notes ? `<p><b>Notes:</b> ${notes}</p>` : ''}`
    ).catch(() => {});

    const notesHtml = notes ? `<p><b>Your notes:</b> ${notes}</p>` : '';
    sendEmail(
      `Your Sranan Kitchen order is confirmed! 🥘`,
      `<div style="font-family:sans-serif;max-width:520px;margin:auto">
        <h2 style="color:#2d6a4f">Thanks for your order, ${customerName}!</h2>
        <p>We're preparing your Surinamese dishes. Here's what you ordered:</p>
        ${orderTable}
        ${notesHtml}
        <p style="margin-top:1.5rem;color:#1b4332">📍 Paramaribo, Suriname<br>📞 (597) 812-3456</p>
        <p style="color:#aaa;font-size:.85rem">Sranan Kitchen — Authentic Surinamese cuisine, made with love.</p>
       </div>`,
      customerEmail
    ).catch(() => {});

    for (const { item } of orderItems) {
      const r = await db.execute({ sql: 'SELECT * FROM food_items WHERE id = ?', args: [item.id] });
      const updated = r.rows[0];
      if (Number(updated.quantity) <= Number(updated.low_stock_threshold)) {
        sendEmail(
          `⚠️ Low Stock — Sranan Kitchen: ${updated.name}`,
          `<h2 style="color:#2d6a4f">Low Stock Alert — Sranan Kitchen</h2>
           <ul><li>${updated.emoji} <b>${updated.name}</b>: ${updated.quantity} remaining (threshold: ${updated.low_stock_threshold})</li></ul>`
        ).catch(() => {});
      }
    }

    res.json({
      ok: true,
      total,
      items: orderItems.map(({ item, quantity }) => ({ name: item.name, emoji: item.emoji, quantity, price: Number(item.price) }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Orders (admin) ───────────────────────────────────────────────────────────

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const { status } = req.query;
    const sql  = status
      ? 'SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC'
      : 'SELECT * FROM orders ORDER BY created_at DESC';
    const args = status ? [status] : [];
    const result = await db.execute({ sql, args });
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/orders/:id/handle', requireAuth, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT * FROM orders WHERE id = ?', args: [req.params.id] });
    const order = r.rows[0];
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.status === 'handled') return res.status(400).json({ error: 'Order already handled' });

    await db.execute({
      sql:  'UPDATE orders SET status = ?, handled_at = ? WHERE id = ?',
      args: ['handled', new Date().toISOString(), req.params.id],
    });

    const items = JSON.parse(order.items_json);
    const itemRows = items.map(i =>
      `<tr><td>${i.emoji} ${i.name}</td><td>×${i.quantity}</td><td>$${(i.price * i.quantity).toFixed(2)}</td></tr>`
    ).join('');
    const orderTable = `
      <table border="0" cellpadding="6" style="border-collapse:collapse;width:100%;font-family:sans-serif">
        <thead><tr style="background:#f0f0f0"><th align="left">Item</th><th>Qty</th><th>Price</th></tr></thead>
        <tbody>${itemRows}</tbody>
        <tfoot><tr><td colspan="2"><b>Total</b></td><td><b>$${Number(order.total).toFixed(2)}</b></td></tr></tfoot>
      </table>`;

    let subject, html;
    if (order.type === 'food') {
      subject = `✝ Uw bestelling is klaar — Zondagschool Keuken`;
      html = `<div style="font-family:Georgia,serif;max-width:520px;margin:auto;color:#2c2011">
        <div style="background:#1d3557;padding:1.5rem 2rem;text-align:center">
          <h1 style="color:white;font-style:italic;margin:0">✝ Zondagschool Keuken</h1>
          <p style="color:#d4a843;margin:.3rem 0 0;font-family:sans-serif;font-size:.9rem">Surinaamse Keuken</p>
        </div>
        <div style="padding:2rem;background:#fdf6e3">
          <h2 style="color:#1d3557">Uw bestelling is klaar, ${order.customer_name}!</h2>
          <p style="line-height:1.8;font-family:sans-serif">Goed nieuws — uw bestelling staat klaar om afgehaald te worden. Wij wensen u smakelijk eten. God zegene u!</p>
          ${orderTable}
          ${order.notes ? `<p style="margin-top:1rem;font-family:sans-serif"><b>Uw opmerking:</b> ${order.notes}</p>` : ''}
          <p style="margin-top:1.5rem;color:#457b9d;font-family:sans-serif;font-size:.9rem">📍 Paramaribo, Suriname<br>📞 (597) 812-3456</p>
          <p style="color:#aaa;font-size:.82rem;font-style:italic;margin-top:1rem">"Proef en zie dat de HEERE goed is." — Psalm 34:9</p>
        </div>
      </div>`;
    } else {
      subject = `🍩 Your Glazed & Amazed order is ready for pickup!`;
      html = `<div style="font-family:sans-serif;max-width:520px;margin:auto">
        <div style="background:#f7567c;padding:1.5rem 2rem;text-align:center">
          <h1 style="color:white;margin:0">🍩 Glazed &amp; Amazed</h1>
        </div>
        <div style="padding:2rem;background:#fff8f0">
          <h2 style="color:#d63b60">Your order is ready, ${order.customer_name}!</h2>
          <p style="line-height:1.8">Great news — your donuts are fresh out of the fryer and ready for pickup. Come get them while they're warm!</p>
          ${orderTable}
          ${order.notes ? `<p style="margin-top:1rem"><b>Your notes:</b> ${order.notes}</p>` : ''}
          <p style="margin-top:1.5rem;color:#7a5230">📍 123 Sprinkle Lane, Bakerville, CA 90210<br>📞 (555) 867-5309</p>
          <p style="color:#aaa;font-size:.85rem">Glazed &amp; Amazed — Made fresh daily.</p>
        </div>
      </div>`;
    }

    await sendEmail(subject, html, order.customer_email);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Start ─────────────────────────────────────────────────────────────────────

init().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🍩 Glazed & Amazed running at http://localhost:${PORT}`);
    console.log(`🔐 Admin portal: http://localhost:${PORT}/admin.html`);
    console.log(`   Default login: admin / donuts123\n`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
