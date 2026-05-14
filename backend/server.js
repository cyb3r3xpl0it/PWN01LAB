const express = require('express');
const mysql   = require('mysql2');
const cors    = require('cors');
const bodyParser = require('body-parser');
const fs      = require('fs');
const path    = require('path');
const http    = require('http');
const https   = require('https');
const { exec } = require('child_process');
const jwt     = require('jsonwebtoken');
const ejs     = require('ejs');
const xml2js  = require('xml2js');

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

const JWT_SECRET = 'secret';

// ─────────────────────────────────────────────
// VULN 1: SQL Injection — login sin sanitizar
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (err) {
      return res.json({ success: false, error: err.sqlMessage, query });
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
  res.json({ query: q, results: [] });
});

app.post('/api/messages', (req, res) => {
  const { username, content } = req.body;
  db.query('INSERT INTO messages (username, content) VALUES (?, ?)', [username, content], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/messages', (req, res) => {
  db.query('SELECT * FROM messages ORDER BY created_at DESC LIMIT 50', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ─────────────────────────────────────────────
// VULN 3: IDOR — sin verificar ownership
// ─────────────────────────────────────────────
app.get('/api/user', (req, res) => {
  const id = req.query.id;
  db.query('SELECT id, username, email, role, secret FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!results.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(results[0]);
  });
});

// ─────────────────────────────────────────────
// VULN 5: Command Injection — simulado (ping)
// ─────────────────────────────────────────────
app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  exec(`ping -c 2 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ output: stdout || stderr || (err && err.message) || '' });
  });
});

// ─────────────────────────────────────────────
// VULN 6: CSRF — sin token de validación
// ─────────────────────────────────────────────
app.post('/api/change-email', (req, res) => {
  const { user_id, email } = req.body;
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

// ─────────────────────────────────────────────
// VULN 7: Path Traversal — lectura de archivos
// ─────────────────────────────────────────────
app.get('/api/file', (req, res) => {
  const name = req.query.name || 'readme.txt';
  // VULNERABLE: path.join resuelve '..' y permite salir del directorio base
  const filePath = path.join('/app/public', name);
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({ file: name, resolved: filePath, content });
  } catch (e) {
    res.status(404).json({ error: e.message, resolved: filePath });
  }
});

// ─────────────────────────────────────────────
// VULN 8: SSRF — Server-Side Request Forgery
// ─────────────────────────────────────────────
app.post('/api/fetch', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url requerida' });
  // VULNERABLE: hace request al destino que el cliente indique
  const client = url.startsWith('https://') ? https : http;
  try {
    const reqOut = client.get(url, { timeout: 5000 }, (response) => {
      let data = '';
      response.on('data', chunk => { data += chunk; });
      response.on('end', () => res.json({
        status: response.statusCode,
        headers: response.headers,
        body: data.substring(0, 3000),
        flag: 'FLAG{ssrf_internal_access}',
      }));
    });
    reqOut.on('error', err => res.status(500).json({ error: err.message }));
    reqOut.on('timeout', () => { reqOut.destroy(); res.status(408).json({ error: 'Timeout' }); });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 9: JWT débil / algoritmo none
// ─────────────────────────────────────────────
app.post('/api/token', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (err || !results.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = results[0];
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );
    res.json({ token, hint: 'Secreto débil: "secret". Intenta cambiar alg a "none" en el header.' });
  });
});

app.get('/api/admin/flag', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Header: Authorization: Bearer <token>' });
  try {
    const parts = token.split('.');
    if (parts.length < 2) return res.status(400).json({ error: 'Token malformado' });
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    let decoded;
    if (header.alg === 'none') {
      // VULNERABLE: acepta tokens sin firma cuando alg=none
      decoded = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    } else {
      decoded = jwt.verify(token, JWT_SECRET);
    }
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: `Rol '${decoded.role}' insuficiente. Necesitas role:admin` });
    }
    res.json({ success: true, flag: 'FLAG{jwt_alg_none_pwned}', user: decoded });
  } catch (e) {
    res.status(401).json({ error: 'Token inválido: ' + e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 10: Broken Access Control — rol desde query param
// ─────────────────────────────────────────────
app.get('/api/admin/users', (req, res) => {
  // VULNERABLE: confía en el parámetro role enviado por el cliente
  const role = req.query.role;
  if (role !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado. Necesitas ?role=admin', hint: 'El servidor confía en el parámetro que tú envías.' });
  }
  db.query('SELECT id, username, email, role, secret FROM users', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ flag: 'FLAG{bac_admin_bypass}', users: results });
  });
});

// ─────────────────────────────────────────────
// VULN 11: Mass Assignment — escalada de privilegios
// ─────────────────────────────────────────────
app.put('/api/profile', (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'id requerido' });
  const fields = { ...req.body };
  delete fields.id;
  if (!Object.keys(fields).length) return res.status(400).json({ error: 'Sin campos a actualizar' });
  // VULNERABLE: cualquier campo del body se escribe en la BD, incluido 'role'
  const cols = Object.keys(fields).map(f => `\`${f}\` = ?`).join(', ');
  const vals = [...Object.values(fields), Number(id)];
  db.query(`UPDATE users SET ${cols} WHERE id = ?`, vals, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    const escalated = 'role' in fields;
    res.json({
      success: true,
      updated: fields,
      flag: escalated ? 'FLAG{mass_assign_privesc}' : undefined,
      note: escalated ? `Rol cambiado a '${fields.role}' sin autorización` : undefined,
    });
  });
});

// ─────────────────────────────────────────────
// VULN 12: Open Redirect — sin validación de destino
// ─────────────────────────────────────────────
app.get('/api/redirect', (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'url requerida' });
  // VULNERABLE: redirige a cualquier URL sin verificar dominio
  res.redirect(302, url);
});

// ─────────────────────────────────────────────
// VULN 13: Prototype Pollution — deep merge sin filtrar __proto__
// ─────────────────────────────────────────────
function deepMergeVuln(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] !== null && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      deepMergeVuln(target[key], source[key]); // VULNERABLE: propaga __proto__
    } else {
      target[key] = source[key];
    }
  }
}

app.post('/api/merge', (req, res) => {
  const base = {};
  deepMergeVuln(base, req.body);
  const polluted = ({}).polluted;
  if (polluted !== undefined) {
    try { delete Object.prototype.polluted; } catch (_) {}
  }
  res.json({
    merged: base,
    polluted: polluted,
    flag: polluted !== undefined ? 'FLAG{prototype_pollution_pwned}' : undefined,
    note: polluted !== undefined
      ? `Object.prototype.polluted = "${polluted}" — todos los objetos del proceso estuvieron afectados`
      : 'Sin contaminación detectada. Prueba con {"__proto__":{"polluted":"PWNED"}}',
  });
});

// ─────────────────────────────────────────────
// VULN 14: XXE — entidades externas del sistema
// ─────────────────────────────────────────────
app.post('/api/xml', (req, res) => {
  const xmlInput = req.body.xml || '<root></root>';
  // VULNERABLE: resuelve entidades SYSTEM del DTD leyendo archivos del servidor
  const systemMatch = xmlInput.match(/SYSTEM\s+["']([^"']+)["']/);
  if (systemMatch) {
    const filePath = systemMatch[1];
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      return res.json({
        flag: 'FLAG{xxe_file_read_success}',
        entity_resolved: content.substring(0, 1000),
        file: filePath,
      });
    } catch (e) {
      return res.status(500).json({ error: `No se pudo leer '${filePath}': ${e.message}` });
    }
  }
  xml2js.parseString(xmlInput, { explicitArray: false }, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ parsed: result, hint: 'Agrega una entidad SYSTEM para leer archivos del servidor' });
  });
});

// ─────────────────────────────────────────────
// VULN 15: SSTI — Server-Side Template Injection con EJS
// ─────────────────────────────────────────────
app.post('/api/render', (req, res) => {
  const template = req.body.template || 'Hola <%= user %>!';
  try {
    // VULNERABLE: renderiza template controlado por el usuario
    const output = ejs.render(template, { user: 'guest' });
    res.json({ output, flag: /require|execSync|exec|spawn/i.test(template) ? 'FLAG{ssti_rce_via_ejs}' : undefined });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 16: Insecure Deserialization — eval en JSON reviver
// ─────────────────────────────────────────────
app.post('/api/decode', (req, res) => {
  try {
    const raw = Buffer.from(req.body.data || '', 'base64').toString('utf8');
    // VULNERABLE: ejecuta funciones embebidas en el JSON deserializado
    const obj = JSON.parse(raw, (key, value) => {
      if (typeof value === 'string' && value.startsWith('_FUNC_:')) {
        return eval(value.slice(7)); // ejecución de código arbitrario
      }
      return value;
    });
    const hasExec = raw.includes('_FUNC_:');
    res.json({
      result: obj,
      flag: hasExec ? 'FLAG{insecure_deserialize_rce}' : undefined,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Health check
app.get('/api/health', (_, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`VulnLab backend running on :${PORT}`));
