const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { initDb, queryAll, queryGet, runSql } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hr-system-secret-change-in-production';

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ──
function authenticateToken(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}
// Employees may only act on their own linked record; managers on their reports; HR admin on anyone.
function canAccessEmployee(user, employeeId) {
  if (user.role === 'hr_admin') return true;
  if (user.role === 'employee') return user.employeeId === employeeId;
  if (user.role === 'manager') {
    if (user.employeeId === employeeId) return true;
    const emp = queryGet('SELECT manager_id FROM employees WHERE id = ?', [employeeId]);
    return emp && emp.manager_id === user.employeeId;
  }
  return false;
}
function logAction(user, action, employeeId, details) {
  runSql('INSERT INTO audit_log (user, action, employee_id, details) VALUES (?, ?, ?, ?)',
    [user || 'system', action, employeeId || null, details || null]);
}

// ════════════════ AUTH ════════════════
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = queryGet('SELECT * FROM users WHERE username = ?', [(username || '').toLowerCase()]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const payload = { id: user.id, username: user.username, role: user.role, employeeId: user.employee_id, fullName: user.full_name };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
  logAction(user.username, 'login');
  res.json({ token, user: { ...payload, mustChangePassword: !!user.must_change_password } });
});

app.post('/api/auth/change-password', authenticateToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = queryGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(400).json({ error: 'Current password incorrect' });
  }
  runSql('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
    [bcrypt.hashSync(newPassword, 10), req.user.id]);
  res.json({ message: 'Password changed' });
});

// ════════════════ EMPLOYEES ════════════════
const EMP_FIELDS = ['title','employee_number','first_name','last_name','preferred_name','date_of_birth','gender','ni_number',
  'address_line1','address_line2','city','postcode','personal_email','work_email','mobile_phone','home_phone',
  'job_title','department','site','manager_id','employment_type','working_hours','notice_period','start_date','end_date',
  'probation_end_date','status','salary','pay_frequency','bank_sort_code','bank_account','holiday_allowance','photo','notes'];

app.get('/api/employees', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  let rows = queryAll('SELECT * FROM employees ORDER BY last_name, first_name');
  if (req.user.role === 'manager') rows = rows.filter(e => e.manager_id === req.user.employeeId);
  if (req.user.role !== 'hr_admin') rows = rows.map(stripSensitive);
  res.json(rows);
});

app.get('/api/employees/:id', authenticateToken, (req, res) => {
  if (!canAccessEmployee(req.user, req.params.id)) return res.status(403).json({ error: 'Forbidden' });
  const emp = queryGet('SELECT * FROM employees WHERE id = ?', [req.params.id]);
  if (!emp) return res.status(404).json({ error: 'Not found' });
  res.json(req.user.role === 'hr_admin' || req.user.employeeId === emp.id ? emp : stripSensitive(emp));
});

app.post('/api/employees', authenticateToken, requireRole('hr_admin'), (req, res) => {
  const id = uuidv4();
  const data = req.body;
  const cols = ['id', ...EMP_FIELDS];
  const vals = [id, ...EMP_FIELDS.map(f => data[f] ?? null)];
  runSql(`INSERT INTO employees (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`, vals);
  logAction(req.user.username, 'employee_create', id, `${data.first_name} ${data.last_name}`);
  res.status(201).json(queryGet('SELECT * FROM employees WHERE id = ?', [id]));
});

app.put('/api/employees/:id', authenticateToken, (req, res) => {
  if (!canAccessEmployee(req.user, req.params.id)) return res.status(403).json({ error: 'Forbidden' });
  // Employees may only update their own contact fields
  let fields = EMP_FIELDS;
  if (req.user.role !== 'hr_admin') {
    fields = ['address_line1','address_line2','city','postcode','personal_email','mobile_phone','home_phone'];
  }
  const data = req.body;
  const sets = fields.filter(f => f in data);
  if (!sets.length) return res.status(400).json({ error: 'No updatable fields' });
  runSql(`UPDATE employees SET ${sets.map(f => `${f} = ?`).join(',')}, updated_at = datetime('now') WHERE id = ?`,
    [...sets.map(f => data[f]), req.params.id]);
  logAction(req.user.username, 'employee_update', req.params.id);
  res.json(queryGet('SELECT * FROM employees WHERE id = ?', [req.params.id]));
});

app.delete('/api/employees/:id', authenticateToken, requireRole('hr_admin'), (req, res) => {
  runSql('DELETE FROM employees WHERE id = ?', [req.params.id]);
  logAction(req.user.username, 'employee_delete', req.params.id);
  res.json({ message: 'Deleted' });
});

function stripSensitive(emp) {
  const { salary, bank_sort_code, bank_account, ni_number, ...rest } = emp;
  return rest;
}

// ════════════════ CONTACTS ════════════════
app.get('/api/employees/:id/contacts', authenticateToken, (req, res) => {
  if (!canAccessEmployee(req.user, req.params.id)) return res.status(403).json({ error: 'Forbidden' });
  res.json(queryAll('SELECT * FROM contacts WHERE employee_id = ?', [req.params.id]));
});
app.post('/api/employees/:id/contacts', authenticateToken, (req, res) => {
  if (!canAccessEmployee(req.user, req.params.id)) return res.status(403).json({ error: 'Forbidden' });
  const id = uuidv4();
  const { name, relationship, phone, email, address } = req.body;
  runSql('INSERT INTO contacts (id, employee_id, name, relationship, phone, email, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, req.params.id, name, relationship || null, phone || null, email || null, address || null]);
  res.status(201).json(queryGet('SELECT * FROM contacts WHERE id = ?', [id]));
});
app.delete('/api/contacts/:id', authenticateToken, (req, res) => {
  runSql('DELETE FROM contacts WHERE id = ?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ════════════════ LEAVE / ABSENCE ════════════════
app.get('/api/leave', authenticateToken, (req, res) => {
  let rows = queryAll('SELECT * FROM leave ORDER BY start_date DESC');
  if (req.user.role === 'employee') rows = rows.filter(l => l.employee_id === req.user.employeeId);
  else if (req.user.role === 'manager') {
    const team = queryAll('SELECT id FROM employees WHERE manager_id = ?', [req.user.employeeId]).map(e => e.id);
    rows = rows.filter(l => team.includes(l.employee_id) || l.employee_id === req.user.employeeId);
  }
  res.json(rows);
});

app.post('/api/leave', authenticateToken, (req, res) => {
  const { employee_id, type, start_date, end_date, days, half_day, reason } = req.body;
  const targetEmp = req.user.role === 'employee' ? req.user.employeeId : employee_id;
  if (!canAccessEmployee(req.user, targetEmp)) return res.status(403).json({ error: 'Forbidden' });
  const id = uuidv4();
  // Employee bookings start as pending; HR/manager records are auto-approved.
  const status = req.user.role === 'employee' ? 'pending' : 'approved';
  runSql(`INSERT INTO leave (id, employee_id, type, start_date, end_date, days, half_day, status, reason, decided_by, decided_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, targetEmp, type, start_date, end_date, days, half_day ? 1 : 0, status, reason || null,
     status === 'approved' ? req.user.username : null, status === 'approved' ? new Date().toISOString() : null]);
  logAction(req.user.username, 'leave_create', targetEmp);
  res.status(201).json(queryGet('SELECT * FROM leave WHERE id = ?', [id]));
});

app.post('/api/leave/:id/decision', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  const { decision, note } = req.body; // 'approved' | 'rejected'
  const leave = queryGet('SELECT * FROM leave WHERE id = ?', [req.params.id]);
  if (!leave) return res.status(404).json({ error: 'Not found' });
  if (!canAccessEmployee(req.user, leave.employee_id)) return res.status(403).json({ error: 'Forbidden' });
  runSql('UPDATE leave SET status = ?, decided_by = ?, decided_at = datetime(\'now\'), decision_note = ? WHERE id = ?',
    [decision, req.user.username, note || null, req.params.id]);
  logAction(req.user.username, 'leave_' + decision, leave.employee_id);
  res.json(queryGet('SELECT * FROM leave WHERE id = ?', [req.params.id]));
});

app.delete('/api/leave/:id', authenticateToken, (req, res) => {
  const leave = queryGet('SELECT * FROM leave WHERE id = ?', [req.params.id]);
  if (!leave) return res.status(404).json({ error: 'Not found' });
  // Employees may only cancel their own pending requests
  if (req.user.role === 'employee') {
    if (leave.employee_id !== req.user.employeeId || leave.status !== 'pending') return res.status(403).json({ error: 'Forbidden' });
    runSql('UPDATE leave SET status = ? WHERE id = ?', ['cancelled', req.params.id]);
  } else {
    runSql('DELETE FROM leave WHERE id = ?', [req.params.id]);
  }
  res.json({ message: 'Done' });
});

// ════════════════ REVIEWS ════════════════
app.get('/api/reviews', authenticateToken, (req, res) => {
  let rows = queryAll('SELECT * FROM reviews ORDER BY scheduled_date DESC');
  if (req.user.role === 'employee') rows = rows.filter(r => r.employee_id === req.user.employeeId);
  else if (req.user.role === 'manager') {
    const team = queryAll('SELECT id FROM employees WHERE manager_id = ?', [req.user.employeeId]).map(e => e.id);
    rows = rows.filter(r => team.includes(r.employee_id));
  }
  res.json(rows);
});
app.post('/api/reviews', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  const id = uuidv4();
  const { employee_id, type, period, scheduled_date, status, reviewer_id, self_assessment, manager_comments, overall_rating } = req.body;
  if (!canAccessEmployee(req.user, employee_id)) return res.status(403).json({ error: 'Forbidden' });
  runSql(`INSERT INTO reviews (id, employee_id, type, period, scheduled_date, status, reviewer_id, self_assessment, manager_comments, overall_rating)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, employee_id, type, period, scheduled_date, status || 'scheduled', reviewer_id || req.user.employeeId, self_assessment || null, manager_comments || null, overall_rating || null]);
  res.status(201).json(queryGet('SELECT * FROM reviews WHERE id = ?', [id]));
});
app.put('/api/reviews/:id', authenticateToken, (req, res) => {
  const review = queryGet('SELECT * FROM reviews WHERE id = ?', [req.params.id]);
  if (!review) return res.status(404).json({ error: 'Not found' });
  // Employees may only edit their own self-assessment
  if (req.user.role === 'employee') {
    if (review.employee_id !== req.user.employeeId) return res.status(403).json({ error: 'Forbidden' });
    runSql('UPDATE reviews SET self_assessment = ? WHERE id = ?', [req.body.self_assessment || null, req.params.id]);
  } else {
    if (!canAccessEmployee(req.user, review.employee_id)) return res.status(403).json({ error: 'Forbidden' });
    const f = ['type','period','scheduled_date','status','self_assessment','manager_comments','overall_rating'];
    const sets = f.filter(x => x in req.body);
    const completedAt = req.body.status === 'completed' ? new Date().toISOString() : review.completed_at;
    runSql(`UPDATE reviews SET ${sets.map(x => `${x} = ?`).join(',')}, completed_at = ? WHERE id = ?`,
      [...sets.map(x => req.body[x]), completedAt, req.params.id]);
  }
  res.json(queryGet('SELECT * FROM reviews WHERE id = ?', [req.params.id]));
});

// ════════════════ OBJECTIVES ════════════════
app.get('/api/objectives', authenticateToken, (req, res) => {
  let rows = queryAll('SELECT * FROM objectives');
  if (req.user.role === 'employee') rows = rows.filter(o => o.employee_id === req.user.employeeId);
  res.json(rows);
});
app.post('/api/objectives', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  const id = uuidv4();
  const { employee_id, title, description, target_date, status, progress } = req.body;
  if (!canAccessEmployee(req.user, employee_id)) return res.status(403).json({ error: 'Forbidden' });
  runSql('INSERT INTO objectives (id, employee_id, title, description, target_date, status, progress) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, employee_id, title, description || null, target_date || null, status || 'not_started', progress || 0]);
  res.status(201).json(queryGet('SELECT * FROM objectives WHERE id = ?', [id]));
});
app.put('/api/objectives/:id', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  const f = ['title','description','target_date','status','progress'];
  const sets = f.filter(x => x in req.body);
  runSql(`UPDATE objectives SET ${sets.map(x => `${x} = ?`).join(',')} WHERE id = ?`, [...sets.map(x => req.body[x]), req.params.id]);
  res.json(queryGet('SELECT * FROM objectives WHERE id = ?', [req.params.id]));
});
app.delete('/api/objectives/:id', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  runSql('DELETE FROM objectives WHERE id = ?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ════════════════ DOCUMENTS ════════════════
// File bytes stored on disk under data/documents; metadata in DB.
const fs = require('fs');
app.get('/api/documents', authenticateToken, (req, res) => {
  const { employee_id } = req.query;
  if (employee_id) {
    if (!canAccessEmployee(req.user, employee_id)) return res.status(403).json({ error: 'Forbidden' });
    return res.json(queryAll('SELECT id, employee_id, category, title, filename, mime_type, description, uploaded_by, uploaded_at FROM documents WHERE employee_id = ?', [employee_id]));
  }
  // company-wide docs are visible to everyone
  res.json(queryAll('SELECT id, employee_id, category, title, filename, mime_type, description, uploaded_by, uploaded_at FROM documents WHERE employee_id IS NULL'));
});
app.post('/api/documents', authenticateToken, requireRole('hr_admin'), (req, res) => {
  const { employee_id, category, title, filename, mime_type, data, description } = req.body;
  const id = uuidv4();
  const matches = (data || '').match(/^data:.*?;base64,(.+)$/);
  const filePath = path.join('documents', `${id}-${(filename || 'file').replace(/[^\w.\-]/g, '_')}`);
  if (matches) fs.writeFileSync(path.join(__dirname, 'data', filePath), Buffer.from(matches[1], 'base64'));
  runSql('INSERT INTO documents (id, employee_id, category, title, filename, mime_type, file_path, description, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [id, employee_id || null, category, title, filename, mime_type, filePath, description || null, req.user.username]);
  logAction(req.user.username, 'document_upload', employee_id || null, title);
  res.status(201).json({ id });
});
app.get('/api/documents/:id/download', authenticateToken, (req, res) => {
  const doc = queryGet('SELECT * FROM documents WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  if (doc.employee_id && !canAccessEmployee(req.user, doc.employee_id)) return res.status(403).json({ error: 'Forbidden' });
  res.download(path.join(__dirname, 'data', doc.file_path), doc.filename);
});
app.delete('/api/documents/:id', authenticateToken, requireRole('hr_admin'), (req, res) => {
  const doc = queryGet('SELECT * FROM documents WHERE id = ?', [req.params.id]);
  if (doc && doc.file_path) { const p = path.join(__dirname, 'data', doc.file_path); if (fs.existsSync(p)) fs.unlinkSync(p); }
  runSql('DELETE FROM documents WHERE id = ?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ════════════════ TASKS ════════════════
app.get('/api/tasks', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  let rows = queryAll('SELECT * FROM tasks ORDER BY due_date');
  if (req.user.role === 'manager') rows = rows.filter(t => t.assigned_to === req.user.id);
  res.json(rows);
});
app.post('/api/tasks', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  const id = uuidv4();
  const { title, description, assigned_to, related_employee_id, due_date, reminder_date, priority, status } = req.body;
  runSql(`INSERT INTO tasks (id, title, description, assigned_to, related_employee_id, due_date, reminder_date, priority, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, title, description || null, assigned_to || req.user.id, related_employee_id || null, due_date || null, reminder_date || null, priority || 'medium', status || 'open']);
  res.status(201).json(queryGet('SELECT * FROM tasks WHERE id = ?', [id]));
});
app.put('/api/tasks/:id', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  const f = ['title','description','assigned_to','related_employee_id','due_date','reminder_date','priority','status'];
  const sets = f.filter(x => x in req.body);
  const completedAt = req.body.status === 'done' ? new Date().toISOString() : null;
  runSql(`UPDATE tasks SET ${sets.map(x => `${x} = ?`).join(',')}, completed_at = ? WHERE id = ?`,
    [...sets.map(x => req.body[x]), completedAt, req.params.id]);
  res.json(queryGet('SELECT * FROM tasks WHERE id = ?', [req.params.id]));
});
app.delete('/api/tasks/:id', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  runSql('DELETE FROM tasks WHERE id = ?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ════════════════ USERS (HR admin) ════════════════
app.get('/api/users', authenticateToken, requireRole('hr_admin'), (req, res) => {
  res.json(queryAll('SELECT id, username, role, employee_id, full_name, created_at FROM users ORDER BY username'));
});
app.post('/api/users', authenticateToken, requireRole('hr_admin'), (req, res) => {
  const { username, password, role, employee_id, full_name } = req.body;
  if (queryGet('SELECT id FROM users WHERE username = ?', [username.toLowerCase()])) return res.status(409).json({ error: 'Username exists' });
  const id = uuidv4();
  runSql('INSERT INTO users (id, username, password_hash, role, employee_id, full_name, must_change_password) VALUES (?, ?, ?, ?, ?, ?, 1)',
    [id, username.toLowerCase(), bcrypt.hashSync(password, 10), role, employee_id || null, full_name]);
  logAction(req.user.username, 'user_create', null, username);
  res.status(201).json({ id });
});
app.put('/api/users/:id', authenticateToken, requireRole('hr_admin'), (req, res) => {
  const f = ['role','employee_id','full_name'];
  const sets = f.filter(x => x in req.body);
  if (sets.length) runSql(`UPDATE users SET ${sets.map(x => `${x} = ?`).join(',')} WHERE id = ?`, [...sets.map(x => req.body[x]), req.params.id]);
  if (req.body.password) runSql('UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?', [bcrypt.hashSync(req.body.password, 10), req.params.id]);
  res.json({ message: 'Saved' });
});
app.delete('/api/users/:id', authenticateToken, requireRole('hr_admin'), (req, res) => {
  const u = queryGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (u && u.username === 'admin') return res.status(400).json({ error: 'Cannot delete admin' });
  runSql('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ════════════════ REPORTS ════════════════
app.get('/api/reports/headcount', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  res.json({
    bySite: queryAll("SELECT site, COUNT(*) n FROM employees WHERE status='active' GROUP BY site"),
    byDepartment: queryAll("SELECT department, COUNT(*) n FROM employees WHERE status='active' GROUP BY department"),
    total: queryGet("SELECT COUNT(*) n FROM employees WHERE status='active'").n
  });
});
app.get('/api/reports/absence', authenticateToken, requireRole('hr_admin', 'manager'), (req, res) => {
  const { from, to } = req.query;
  res.json(queryAll(`SELECT employee_id, COUNT(*) instances, SUM(days) days FROM leave
    WHERE type='sickness' AND status='approved' AND start_date >= ? AND start_date <= ? GROUP BY employee_id`,
    [from || '1900-01-01', to || '2999-12-31']));
});

// ════════════════ SETTINGS ════════════════
app.get('/api/settings', authenticateToken, (req, res) => {
  const rows = queryAll('SELECT * FROM settings');
  res.json(Object.fromEntries(rows.map(r => [r.key, r.value])));
});
app.put('/api/settings/:key', authenticateToken, requireRole('hr_admin'), (req, res) => {
  runSql('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?',
    [req.params.key, req.body.value, req.body.value]);
  res.json({ message: 'Saved' });
});

// SPA fallback
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

(async () => {
  await initDb();
  app.listen(PORT, '0.0.0.0', () => console.log(`HR System running on http://0.0.0.0:${PORT}`));
})();
