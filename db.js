const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');

const db = createClient({
  url:       process.env.TURSO_URL   || 'file:donuts.db',
  authToken: process.env.TURSO_TOKEN || undefined,
});

async function init() {
  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS donuts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      emoji TEXT DEFAULT '🍩',
      available INTEGER DEFAULT 1,
      quantity INTEGER DEFAULT 0,
      low_stock_threshold INTEGER DEFAULT 5
    );

    CREATE TABLE IF NOT EXISTS admin (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT ''
    );
  `);

  // Idempotent migrations
  try { await db.execute('ALTER TABLE donuts ADD COLUMN quantity INTEGER DEFAULT 0'); } catch {}
  try { await db.execute('ALTER TABLE donuts ADD COLUMN low_stock_threshold INTEGER DEFAULT 5'); } catch {}

  // Default admin
  const adminRow = await db.execute('SELECT id FROM admin WHERE id = 1');
  if (!adminRow.rows.length) {
    const hash = bcrypt.hashSync('donuts123', 10);
    await db.execute({ sql: 'INSERT INTO admin (id, username, password_hash) VALUES (1, ?, ?)', args: ['admin', hash] });
  }

  // Default settings
  const confirmBodyDefault = '<div style="font-family:sans-serif;max-width:520px;margin:auto"><h2 style="color:#f7567c">Thanks for your order, {{customerName}}!</h2><p>We\'re getting your donuts ready. Here\'s what you ordered:</p>{{orderTable}}{{notes}}<p style="margin-top:1.5rem;color:#7a5230">📍 123 Sprinkle Lane, Bakerville, CA 90210<br>📞 (555) 867-5309</p><p style="color:#aaa;font-size:.85rem">Glazed &amp; Amazed — Made fresh daily.</p></div>';
  const settingDefaults = [
    ['brevo_key', ''], ['smtp_from', ''], ['smtp_user', ''], ['notify_email', 'chivarao@gmail.com'],
    ['order_confirm_subject', 'Your Glazed & Amazed order is confirmed! 🍩'],
    ['order_confirm_body', confirmBodyDefault],
  ];
  for (const [k, v] of settingDefaults) {
    await db.execute({ sql: 'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', args: [k, v] });
  }

  // Seed menu if empty
  const count = await db.execute('SELECT COUNT(*) as c FROM donuts');
  if (Number(count.rows[0].c) === 0) {
    const donuts = [
      ['Classic Glazed',   'Pillowy yeast donut with our signature vanilla glaze. The original. The legend.',         2.50, '🍩', 24, 5],
      ['Strawberry Dream', 'Pink strawberry glaze topped with real freeze-dried strawberry crumbles.',                3.25, '🍓', 18, 5],
      ['Double Chocolate', 'Chocolate cake donut dipped in dark chocolate ganache and chocolate sprinkles.',          3.25, '🍫', 18, 5],
      ['Lemon Burst',      'Light and airy with a zesty lemon curd filling and powdered sugar dusting.',              3.50, '🍋', 12, 4],
      ['Cookies & Cream',  "Vanilla glaze piled high with crushed Oreo cookies. Every kid's favorite.",              3.75, '🍦', 15, 5],
      ['Maple Bacon',      'Sweet maple glaze topped with crispy candied bacon. Sweet meets savory perfection.',      4.00, '🥓', 10, 3],
      ['Apple Fritter',    'Old-fashioned apple fritter with cinnamon, chunks of apple, and honey glaze.',           4.25, '🍎',  8, 3],
      ['Rainbow Sprinkle', 'Birthday cake glaze loaded with rainbow sprinkles. Pure joy in every bite.',             3.00, '🌈', 20, 5],
    ];
    for (const [name, description, price, emoji, quantity, low_stock_threshold] of donuts) {
      await db.execute({
        sql:  'INSERT INTO donuts (name, description, price, emoji, quantity, low_stock_threshold) VALUES (?, ?, ?, ?, ?, ?)',
        args: [name, description, price, emoji, quantity, low_stock_threshold],
      });
    }
  }
}

module.exports = { db, init };
