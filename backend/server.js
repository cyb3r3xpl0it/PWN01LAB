const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createPool({
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || 'vulnlab',
  database: process.env.DB_NAME || 'vulnlab',
  waitForConnections: true,
  connectionLimit: 10,
});

// ─────────────────────────────────────────────
// VULN 1: SQL Injection — login sin sanitizar
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  // VULNERBLE: concatenación directa
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (err) {
      return res.json({
        success: false,
        error: err.sqlMessage,  // también vulnerable: expone error SQL
        query,
      });
    }
    if (results.length > 0) {
      return res.json({
        success: true,
        message: `Bienvenido, ${results[0].username} (${results[0].role})`,
        user: results[0],
        query,
      });
    }
    res.json({ success: false, message: 'Credenciales incorrectas', query });
  });
});

// ─────────────────────────────────────────────
// VULN 2 & 4: XSS — búsqueda y mensajes sin escape
// ─────────────────────────────────────────────
app.get('/api/search', (req, res) => {
  const q = req.query.q || '';
  // Refleja el input sin sanitizar
  res.json({ query: q, results: [] });
});

app.post('/api/messages', (req, res) => {
  const { username, content } = req.body;
  // VULNERABLE: guarda HTML/JS sin sanitizar
  db.query('INSERT INTO messages (username, content) VALUES (?, ?)', [username, content], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/messages', (req, res) => {
  db.query('SELECT * FROM messages ORDER BY created_at DESC LIMIT 50', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    // Devuelve contenido sin sanitizar
    res.json(results);
  });
});

// ─────────────────────────────────────────────
// VULN 3: IDOR — sin verificar ownership
// ─────────────────────────────────────────────
app.get('/api/user', (req, res) => {
  const id = req.query.id;
  // VULNERABLE: sin verificar sesión ni ownership
  db.query('SELECT id, username, email, role, secret FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!results.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(results[0]);
  });
});

// ─────────────────────────────────────────────
// VULN 5: Command Injection — simulado (ping)
// ─────────────────────────────────────────────
const { exec } = require('child_process');
app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  // VULNERABLE: shell injection via concatenación
  exec(`ping -c 2 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ output: stdout || stderr || (err && err.message) || '' });
  });
});

// ─────────────────────────────────────────────
// VULN 6: CSRF — sin token de validación
// ─────────────────────────────────────────────
app.post('/api/change-email', (req, res) => {
  const { user_id, email } = req.body;
  // VULNERABLE: sin verificar CSRF token ni sesión
  db.query('UPDATE emails SET email = ? WHERE user_id = ?', [email, user_id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: `Email actualizado a: ${email}` });
  });
});

app.get('/api/email', (req, res) => {
  const { user_id } = req.query;
  db.query('SELECT email FROM emails WHERE user_id = ?', [user_id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results[0] || {});
  });
});

// Health check
app.get('/api/health', (_, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`VulnLab backend running on :${PORT}`));
