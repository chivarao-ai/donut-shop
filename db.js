const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Database(path.join(__dirname, 'donuts.db'));

db.exec(`
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

// Idempotent migrations for installs that predate the quantity columns
try { db.exec('ALTER TABLE donuts ADD COLUMN quantity INTEGER DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE donuts ADD COLUMN low_stock_threshold INTEGER DEFAULT 5'); } catch {}

// Default admin account
const adminRow = db.prepare('SELECT id FROM admin WHERE id = 1').get();
if (!adminRow) {
  const hash = bcrypt.hashSync('donuts123', 10);
  db.prepare('INSERT INTO admin (id, username, password_hash) VALUES (1, ?, ?)').run('admin', hash);
}

// Default email settings
const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
[
  ['smtp_host',    ''],
  ['smtp_port',    '587'],
  ['smtp_user',    ''],
  ['smtp_pass',    ''],
  ['smtp_from',    ''],
  ['notify_email', 'chivarao@gmail.com'],
].forEach(([k, v]) => insertSetting.run(k, v));

// Seed initial menu if empty
const { c } = db.prepare('SELECT COUNT(*) as c FROM donuts').get();
if (c === 0) {
  const insert = db.prepare(
    'INSERT INTO donuts (name, description, price, emoji, quantity, low_stock_threshold) VALUES (?, ?, ?, ?, ?, ?)'
  );
  [
    ['Classic Glazed',   'Pillowy yeast donut with our signature vanilla glaze. The original. The legend.',         2.50, '🍩', 24, 5],
    ['Strawberry Dream', 'Pink strawberry glaze topped with real freeze-dried strawberry crumbles.',                3.25, '🍓', 18, 5],
    ['Double Chocolate', 'Chocolate cake donut dipped in dark chocolate ganache and chocolate sprinkles.',          3.25, '🍫', 18, 5],
    ['Lemon Burst',      'Light and airy with a zesty lemon curd filling and powdered sugar dusting.',              3.50, '🍋', 12, 4],
    ['Cookies & Cream',  "Vanilla glaze piled high with crushed Oreo cookies. Every kid's favorite.",              3.75, '🍦', 15, 5],
    ['Maple Bacon',      'Sweet maple glaze topped with crispy candied bacon. Sweet meets savory perfection.',      4.00, '🥓', 10, 3],
    ['Apple Fritter',    'Old-fashioned apple fritter with cinnamon, chunks of apple, and honey glaze.',           4.25, '🍎',  8, 3],
    ['Rainbow Sprinkle', 'Birthday cake glaze loaded with rainbow sprinkles. Pure joy in every bite.',             3.00, '🌈', 20, 5],
  ].forEach(row => insert.run(...row));
}

module.exports = db;
