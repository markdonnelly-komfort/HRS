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
      work_phone TEXT,
      work_mobile TEXT,
      is_director INTEGER DEFAULT 0,
      workplace_roles TEXT,          -- JSON array, e.g. ["First aider","Fire warden"]
      leaving_reason TEXT,
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
      ann_seen_at TEXT,
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
      ack INTEGER DEFAULT 0,
      ack_deadline TEXT,
      audience TEXT,                 -- JSON {type: all|managers|hr|departments|sites|people, values: [...]}
      review_date TEXT,
      uploaded_by TEXT,
      uploaded_at TEXT DEFAULT (datetime('now'))
    )
  `);
  // "Read and understood" confirmations for company documents with ack = 1
  db.run(`
    CREATE TABLE IF NOT EXISTS doc_acks (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL REFERENCES documents(id),
      employee_id TEXT NOT NULL REFERENCES employees(id),
      acknowledged_at TEXT DEFAULT (datetime('now')),
      user TEXT,
      UNIQUE(document_id, employee_id)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      job_title TEXT NOT NULL,
      department TEXT,
      site TEXT,
      employment_type TEXT,
      start_date TEXT,
      end_date TEXT,
      reason TEXT,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS one_to_ones (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      with_id TEXT REFERENCES employees(id),
      type TEXT,
      date TEXT,
      time TEXT,
      location TEXT,
      agenda TEXT,
      status TEXT NOT NULL DEFAULT 'scheduled' CHECK(status IN ('requested','scheduled','completed','declined','cancelled')),
      notes TEXT,
      actions TEXT,
      private_notes TEXT,
      employee_notes TEXT,
      requested_by TEXT,
      decided_by TEXT,
      decided_at TEXT,
      completed_at TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);
  // Company-wide closed days. Bank holidays are on top of allowance; shutdown
  // days either come out of allowance (deducts = 1) or are free.
  db.run(`
    CREATE TABLE IF NOT EXISTS company_days (
      id TEXT PRIMARY KEY,
      date TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('bank_holiday','shutdown')),
      deducts INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS return_to_work (
      leave_id TEXT PRIMARY KEY REFERENCES leave(id),
      employee_id TEXT NOT NULL REFERENCES employees(id),
      interview_date TEXT,
      returned_date TEXT,
      reason TEXT,
      certification TEXT,
      work_related TEXT,
      accident_book TEXT,
      fitness TEXT,
      oh_referral TEXT,
      support TEXT,
      notes TEXT,
      employee_comments TEXT,
      bradford_spells INTEGER,
      bradford_days REAL,
      bradford_score REAL,
      conducted_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);
  // E-signature requests: one per employee per document. The signed PDF carries
  // a certificate page; file_hash is the SHA-256 of the original as sent.
  db.run(`
    CREATE TABLE IF NOT EXISTS sign_requests (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      title TEXT NOT NULL,
      message TEXT,
      due_date TEXT,
      category TEXT,
      file_name TEXT,
      file_path TEXT,
      file_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','signed','declined','cancelled')),
      signers TEXT,          -- JSON: ordered [{role: employee|manager|hr, employee_id, status, name, signed_at, method, user, viewed_at, signer_ip}]
      sent_by TEXT,
      sent_at TEXT DEFAULT (datetime('now')),
      viewed_at TEXT,
      signed_at TEXT,
      signer_name TEXT,
      signature_method TEXT,
      signature_image_path TEXT,
      signed_file_path TEXT,
      signed_hash TEXT,
      signer_ip TEXT,
      document_id TEXT REFERENCES documents(id),
      declined_at TEXT,
      declined_reason TEXT,
      cancelled_at TEXT,
      cancelled_by TEXT
    )
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_sign_requests_emp ON sign_requests(employee_id)');
  // HR-only notes on a person, with an optional reminder date
  db.run(`
    CREATE TABLE IF NOT EXISTS hr_notes (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      text TEXT NOT NULL,
      reminder_date TEXT,
      reminder_done INTEGER DEFAULT 0,
      reminder_done_at TEXT,
      created_by TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_hr_notes_emp ON hr_notes(employee_id)');
  // Saved report-builder definitions (columns / filters / sort / grouping as JSON)
  db.run(`
    CREATE TABLE IF NOT EXISTS saved_reports (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      source TEXT NOT NULL,
      definition TEXT NOT NULL,
      created_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);
  // Asset / equipment register and its issue/return history
  db.run(`
    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT,
      asset_tag TEXT,
      serial TEXT,
      purchase_date TEXT,
      value REAL,
      notes TEXT,
      status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available','issued','repair','lost','retired')),
      employee_id TEXT REFERENCES employees(id),
      issued_date TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS asset_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id TEXT NOT NULL REFERENCES assets(id),
      employee_id TEXT NOT NULL REFERENCES employees(id),
      issued_date TEXT,
      condition_out TEXT,
      notes TEXT,
      issued_by TEXT,
      returned_date TEXT,
      condition_in TEXT,
      return_notes TEXT,
      returned_by TEXT
    )
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_assets_emp ON assets(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_asset_history_asset ON asset_history(asset_id)');
  db.run(`
    CREATE TABLE IF NOT EXISTS announcements (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT,
      audience TEXT DEFAULT 'all',   -- JSON {type: all|departments|sites, values: [...]}
      link TEXT,
      link_text TEXT,
      publish_on TEXT,
      pinned INTEGER DEFAULT 0,
      expires TEXT,
      author TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS leave (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      type TEXT NOT NULL CHECK(type IN ('holiday','sickness','adoption','charity','compassionate','jury_service','maternity','medical','parental','paternity','study','training_day','unauthorised','unpaid','other','adjustment')),
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      days REAL NOT NULL,
      half_day INTEGER DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','cancelled')),
      reason TEXT,
      sickness_type TEXT,
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
  db.run(`
    CREATE TABLE IF NOT EXISTS training (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      title TEXT NOT NULL,
      category TEXT,
      provider TEXT,
      completed_date TEXT,
      expiry_date TEXT,
      notes TEXT,
      file_name TEXT,
      file_path TEXT,
      added_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);
  // Uploaded payslips / P60s / P11Ds — confidential: HR admin + the employee only.
  db.run(`
    CREATE TABLE IF NOT EXISTS pay_documents (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL REFERENCES employees(id),
      doc_type TEXT NOT NULL CHECK(doc_type IN ('payslip','p45','p60','p11d','other')),
      period TEXT,
      tax_year TEXT,
      file_name TEXT,
      mime_type TEXT,
      file_path TEXT,
      uploaded_by TEXT,
      uploaded_at TEXT DEFAULT (datetime('now')),
      viewed_at TEXT
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
  db.run('CREATE INDEX IF NOT EXISTS idx_training_emp ON training(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_paydocs_emp ON pay_documents(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_jobs_emp ON jobs(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_one_to_ones_emp ON one_to_ones(employee_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_doc_acks_doc ON doc_acks(document_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_doc_acks_emp ON doc_acks(employee_id)');

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
