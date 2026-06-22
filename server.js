const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const crypto     = require('crypto');
const path       = require('path');
const { db, init } = require('./db');

// Absolute base URL of the current request (honours Render's proxy headers).
function siteUrl(req) {
  return process.env.SITE_URL || `${req.protocol}://${req.get('host')}`;
}

const app  = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// Behind Render's proxy — required for secure cookies and correct client IPs.
app.set('trust proxy', 1);

// Security headers. CSP is disabled because the pages rely on inline scripts,
// inline event handlers and inline styles; the other helmet protections
// (HSTS, noSniff, frameguard, referrer-policy, etc.) still apply.
app.use(helmet({ contentSecurityPolicy: false }));

app.use(express.json({ limit: '100kb' }));
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'glazed-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 8 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
  }
}));

// Throttle credential-guessing on the login endpoints.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again in a few minutes.' },
});

function requireAuth(req, res, next) {
  if (req.session.admin) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Escape user-supplied text before embedding it in notification email HTML,
// preventing HTML/script injection through names, emails and order notes.
function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isEmail(value) {
  return typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

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

app.post('/api/login', loginLimiter, async (req, res) => {
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

// ── Customer accounts ─────────────────────────────────────────────────────────

function requireCustomer(req, res, next) {
  if (req.session.customer) return next();
  res.status(401).json({ error: 'Please log in' });
}

app.post('/api/customer/register', loginLimiter, async (req, res) => {
  try {
    const name  = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const { password } = req.body;
    if (!name || name.length > 120) return res.status(400).json({ error: 'A valid name is required' });
    if (!isEmail(email))            return res.status(400).json({ error: 'A valid email is required' });
    if (!password || String(password).length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const existing = await db.execute({ sql: 'SELECT id FROM customers WHERE email = ?', args: [email] });
    if (existing.rows.length) return res.status(409).json({ error: 'An account with this email already exists' });

    const result = await db.execute({
      sql:  'INSERT INTO customers (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
      args: [name, email, bcrypt.hashSync(password, 10), new Date().toISOString()],
    });
    req.session.customer = { id: Number(result.lastInsertRowid), name, email };
    res.status(201).json({ ok: true, customer: { name, email } });
  } catch (e) { res.status(500).json({ error: 'Could not create account' }); }
});

app.post('/api/customer/login', loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const { password } = req.body;
    const result = await db.execute({ sql: 'SELECT * FROM customers WHERE email = ?', args: [email] });
    const customer = result.rows[0];
    if (!customer || !bcrypt.compareSync(String(password || ''), customer.password_hash))
      return res.status(401).json({ error: 'Invalid email or password' });
    req.session.customer = { id: Number(customer.id), name: customer.name, email: customer.email };
    res.json({ ok: true, customer: { name: customer.name, email: customer.email } });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/customer/logout', (req, res) => {
  delete req.session.customer;
  res.json({ ok: true });
});

app.get('/api/customer/me', (req, res) => {
  res.json({ customer: req.session.customer || null });
});

app.post('/api/customer/forgot', loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    // Always respond the same way so the endpoint can't be used to probe emails.
    if (isEmail(email)) {
      const result = await db.execute({ sql: 'SELECT * FROM customers WHERE email = ?', args: [email] });
      const customer = result.rows[0];
      if (customer) {
        const token   = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
        await db.execute({ sql: 'UPDATE customers SET reset_token = ?, reset_expires = ? WHERE id = ?', args: [token, expires, customer.id] });
        const link = `${siteUrl(req)}/reset-password.html?token=${token}`;
        sendEmail(
          'Reset your password',
          `<div style="font-family:sans-serif;max-width:520px;margin:auto">
            <h2 style="color:#f7567c">Password reset requested</h2>
            <p>Hi ${esc(customer.name)}, we received a request to reset your password.</p>
            <p><a href="${link}" style="display:inline-block;background:#f7567c;color:#fff;padding:.7rem 1.4rem;border-radius:8px;text-decoration:none">Reset my password</a></p>
            <p style="color:#9a7050;font-size:.85rem">This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
          </div>`,
          customer.email
        ).catch(() => {});
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Request failed' }); }
});

app.post('/api/customer/reset', loginLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token) return res.status(400).json({ error: 'Invalid reset link' });
    if (!password || String(password).length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const result = await db.execute({ sql: 'SELECT * FROM customers WHERE reset_token = ?', args: [String(token)] });
    const customer = result.rows[0];
    if (!customer || !customer.reset_expires || new Date(customer.reset_expires) < new Date())
      return res.status(400).json({ error: 'This reset link is invalid or has expired' });
    await db.execute({
      sql:  'UPDATE customers SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?',
      args: [bcrypt.hashSync(String(password), 10), customer.id],
    });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Reset failed' }); }
});

app.get('/api/customer/orders', requireCustomer, async (req, res) => {
  try {
    const result = await db.execute({
      sql:  'SELECT id, type, items_json, total, status, created_at, handled_at FROM orders WHERE customer_email = ? ORDER BY created_at DESC',
      args: [req.session.customer.email],
    });
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Could not load orders' }); }
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
    if (!customerName || String(customerName).trim().length === 0)
      return res.status(400).json({ error: 'Your name is required' });
    if (String(customerName).length > 120) return res.status(400).json({ error: 'Name is too long' });
    if (!isEmail(customerEmail)) return res.status(400).json({ error: 'A valid email is required' });
    if (notes && String(notes).length > 1000) return res.status(400).json({ error: 'Notes are too long' });
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
      sql:  'INSERT INTO orders (type, customer_name, customer_email, notes, items_json, total, status, created_at, customer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: ['donut', customerName, customerEmail, notes || '', JSON.stringify(orderItems.map(({ donut, quantity }) => ({ name: donut.name, emoji: donut.emoji, quantity, price: Number(donut.price) }))), total, 'pending', new Date().toISOString(), req.session.customer ? req.session.customer.id : null],
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
      `🍩 New Order from ${esc(customerName)}`,
      `<h2 style="color:#f7567c">New Order Received</h2>
       <p><b>Customer:</b> ${esc(customerName)} &lt;${esc(customerEmail)}&gt;</p>
       ${orderTable}
       ${notes ? `<p><b>Notes:</b> ${esc(notes)}</p>` : ''}`
    ).catch(() => {});

    // Send confirmation to the customer (template editable in admin Email Settings)
    const s = await getSettings();
    const notesHtml = notes ? `<p><b>Your notes:</b> ${esc(notes)}</p>` : '';
    const confirmSubject = (s.order_confirm_subject || `Your Glazed & Amazed order is confirmed! 🍩`)
      .replace(/\{\{customerName\}\}/g, esc(customerName))
      .replace(/\{\{total\}\}/g, `$${total.toFixed(2)}`);
    const confirmBody = s.order_confirm_body
      ? s.order_confirm_body
          .replace(/\{\{customerName\}\}/g, esc(customerName))
          .replace(/\{\{orderTable\}\}/g, orderTable)
          .replace(/\{\{notes\}\}/g, notesHtml)
          .replace(/\{\{total\}\}/g, `$${total.toFixed(2)}`)
      : `<div style="font-family:sans-serif;max-width:520px;margin:auto"><h2 style="color:#f7567c">Thanks for your order, ${esc(customerName)}!</h2><p>We're getting your donuts ready. Here's what you ordered:</p>${orderTable}${notesHtml}<p style="margin-top:1.5rem;color:#7a5230">📍 123 Sprinkle Lane, Bakerville, CA 90210<br>📞 (555) 867-5309</p><p style="color:#aaa;font-size:.85rem">Glazed &amp; Amazed — Made fresh daily.</p></div>`;
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
    if (!customerName || String(customerName).trim().length === 0)
      return res.status(400).json({ error: 'Your name is required' });
    if (String(customerName).length > 120) return res.status(400).json({ error: 'Name is too long' });
    if (!isEmail(customerEmail)) return res.status(400).json({ error: 'A valid email is required' });
    if (notes && String(notes).length > 1000) return res.status(400).json({ error: 'Notes are too long' });
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
      sql:  'INSERT INTO orders (type, customer_name, customer_email, notes, items_json, total, status, created_at, customer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: ['food', customerName, customerEmail, notes || '', JSON.stringify(orderItems.map(({ item, quantity }) => ({ name: item.name, emoji: item.emoji, quantity, price: Number(item.price) }))), total, 'pending', new Date().toISOString(), req.session.customer ? req.session.customer.id : null],
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
      `🥘 New Sranan Kitchen Order from ${esc(customerName)}`,
      `<h2 style="color:#2d6a4f">New Order — Sranan Kitchen</h2>
       <p><b>Customer:</b> ${esc(customerName)} &lt;${esc(customerEmail)}&gt;</p>
       ${orderTable}
       ${notes ? `<p><b>Notes:</b> ${esc(notes)}</p>` : ''}`
    ).catch(() => {});

    const notesHtml = notes ? `<p><b>Your notes:</b> ${esc(notes)}</p>` : '';
    sendEmail(
      `Your Sranan Kitchen order is confirmed! 🥘`,
      `<div style="font-family:sans-serif;max-width:520px;margin:auto">
        <h2 style="color:#2d6a4f">Thanks for your order, ${esc(customerName)}!</h2>
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
          <h2 style="color:#1d3557">Uw bestelling is klaar, ${esc(order.customer_name)}!</h2>
          <p style="line-height:1.8;font-family:sans-serif">Goed nieuws — uw bestelling staat klaar om afgehaald te worden. Wij wensen u smakelijk eten. God zegene u!</p>
          ${orderTable}
          ${order.notes ? `<p style="margin-top:1rem;font-family:sans-serif"><b>Uw opmerking:</b> ${esc(order.notes)}</p>` : ''}
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
          <h2 style="color:#d63b60">Your order is ready, ${esc(order.customer_name)}!</h2>
          <p style="line-height:1.8">Great news — your donuts are fresh out of the fryer and ready for pickup. Come get them while they're warm!</p>
          ${orderTable}
          ${order.notes ? `<p style="margin-top:1rem"><b>Your notes:</b> ${esc(order.notes)}</p>` : ''}
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
