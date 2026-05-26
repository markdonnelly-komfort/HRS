const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = path.join(__dirname, 'data', 'hr-system.db');

let db = null;
let SQL = null;

// Save database to disk
function saveDb() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Auto-save every 30 seconds
setInterval(() => { if (db) saveDb(); }, 30000);

async function initDb() {
  if (db) return db;

  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  const docsDir = path.join(dataDir, 'documents');
  if (!fs.existsSync(docsDir)) fs.mkdirSync(docsDir, { recursive: true });

  SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }

  db.run('PRAGMA foreign_keys = ON');
  initializeSchema();
  return db;
}

function getDb() {
  if (!db) throw new Error('Database not initialized. Call initDb() first.');
  return db;
}

function initializeSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS employees (
      id TEXT PRIMARY KEY,
      title TEXT,
      employee_number TEXT,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      preferred_name TEXT,
      date_of_birth TEXT,
      gender TEXT,
      ni_number TEXT,
      address_line1 TEXT,
      address_line2 TEXT,
      city TEXT,
      postcode TEXT,
      personal_email TEXT,
      work_email TEXT,
      mobile_phone TEXT,
      home_phone TEXT,
      job_title TEXT,
      department TEXT,
      site TEXT,
      manager_id TEXT REFERENCES employees(id),
      employment_type TEXT,
      working_hours REAL,
      notice_period TEXT,
      start_date TEXT,
      end_date TEXT,
      probation_end_date TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','on_leave','leaver')),
      salary REAL,
      pay_frequency TEXT,
      bank_sort_code TEXT,
      bank_account TEXT,
      holiday_allowance REAL DEFAULT 25,
      photo TEXT,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('hr_admin','manager','employee')),
      employee_id TEXT REFERENCES employees(id),
      full_name TEXT NOT NULL,
      must_change_password INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS contacts (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      name TEXT NOT NULL,
      relationship TEXT,
      phone TEXT,
      email TEXT,
      address TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      employee_id TEXT REFERENCES employees(id),
      category TEXT,
      title TEXT NOT NULL,
      filename TEXT,
      mime_type TEXT,
      file_path TEXT,
      description TEXT,
      uploaded_by TEXT,
      uploaded_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS leave (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      type TEXT NOT NULL CHECK(type IN ('holiday','sickness','unpaid','maternity','other','adjustment')),
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      days REAL NOT NULL,
      half_day INTEGER DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','cancelled')),
      reason TEXT,
      requested_at TEXT DEFAULT (datetime('now')),
      decided_by TEXT,
      decided_at TEXT,
      decision_note TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS reviews (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      type TEXT NOT NULL CHECK(type IN ('annual','mid_year')),
      period TEXT,
      scheduled_date TEXT,
      status TEXT NOT NULL DEFAULT 'scheduled' CHECK(status IN ('scheduled','in_progress','completed')),
      reviewer_id TEXT REFERENCES employees(id),
      self_assessment TEXT,
      manager_comments TEXT,
      overall_rating TEXT,
      completed_at TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS objectives (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      title TEXT NOT NULL,
      description TEXT,
      target_date TEXT,
      status TEXT NOT NULL DEFAULT 'not_started' CHECK(status IN ('not_started','in_progress','achieved','cancelled')),
      progress INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      assigned_to TEXT REFERENCES users(id),
      related_employee_id TEXT REFERENCES employees(id),
      due_date TEXT,
      reminder_date TEXT,
      priority TEXT DEFAULT 'medium' CHECK(priority IN ('low','medium','high')),
      status TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','done')),
      created_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT DEFAULT (datetime('now')),
      user TEXT,
      action TEXT NOT NULL,
      employee_id TEXT,
      details TEXT
    )
  `);

  // Indexes
  db.run('CREATE INDEX IF NOT EXISTS idx_emp_manager ON employees(manager_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_emp_status ON employees(status)');
  db.run('CREATE INDEX IF NOT EXISTS idx_leave_emp ON leave(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_leave_status ON leave(status)');
  db.run('CREATE INDEX IF NOT EXISTS idx_reviews_emp ON reviews(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_objectives_emp ON objectives(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_docs_emp ON documents(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to)');

  // Default settings
  db.run("INSERT OR IGNORE INTO settings (key, value) VALUES ('holiday_year_start', '01-01')");
  db.run("INSERT OR IGNORE INTO settings (key, value) VALUES ('company_name', 'Komfort Partitioning Ltd')");

  // Seed default HR admin if none exists
  const result = db.exec("SELECT COUNT(*) as count FROM users WHERE role = 'hr_admin'");
  const adminCount = result[0]?.values[0]?.[0] || 0;
  if (adminCount === 0) {
    const hash = bcrypt.hashSync('admin123', 10);
    db.run('INSERT INTO users (id, username, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)',
      [uuidv4(), 'admin', hash, 'hr_admin', 'System Administrator']);
    console.log('Default HR admin created — username: admin, password: admin123');
  }

  saveDb();
}

// Helper: run a query and return array of objects
function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// Helper: run a query and return first row as object
function queryGet(sql, params = []) {
  return queryAll(sql, params)[0] || null;
}

// Helper: run an insert/update/delete
function runSql(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

module.exports = { initDb, getDb, queryAll, queryGet, runSql, saveDb };
