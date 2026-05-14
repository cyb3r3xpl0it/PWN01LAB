const express    = require('express');
const mysql      = require('mysql2');
const cors       = require('cors');
const bodyParser = require('body-parser');
const fs         = require('fs');
const path       = require('path');
const http       = require('http');
const https      = require('https');
const { exec }   = require('child_process');
const jwt        = require('jsonwebtoken');
const ejs        = require('ejs');
const xml2js     = require('xml2js');
const multer     = require('multer');
const crypto     = require('crypto');
const AdmZip     = require('adm-zip');

// RSA key pair para VULN 32 (JWT RS256→HS256)
const { privateKey: rsaPrivate, publicKey: rsaPublic } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaPublicPem = rsaPublic.export({ type: 'spki', format: 'pem' });

// Stores en memoria para challenges
const sessions    = {};   // Session Fixation
const twofa_codes = {};   // 2FA Brute Force
const oauth_codes = {};   // OAuth state
const prng_tokens = {};   // Weak PRNG
const webhooks    = {};   // Stored SSRF

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Servir archivos subidos (File Upload RCE)
app.use('/uploads', express.static('/app/uploads'));

const db = mysql.createPool({
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || 'vulnlab',
  database: process.env.DB_NAME || 'vulnlab',
  waitForConnections: true,
  connectionLimit: 10,
});

const JWT_SECRET = 'secret';

// Multer sin restricción de tipo de archivo (VULN 17)
const upload = multer({
  storage: multer.diskStorage({
    destination: '/app/uploads',
    filename: (req, file, cb) => cb(null, file.originalname),
  }),
  // VULNERABLE: sin validación de mimetype ni extensión
});

// ─────────────────────────────────────────────
// VULN 1: SQL Injection — login sin sanitizar
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.query(query, (err, results) => {
    if (err) return res.json({ success: false, error: err.sqlMessage, query });
    if (results.length > 0) {
      return res.json({ success: true, message: `Bienvenido, ${results[0].username} (${results[0].role})`, user: results[0], query });
    }
    res.json({ success: false, message: 'Credenciales incorrectas', query });
  });
});

// ─────────────────────────────────────────────
// VULN 2 & 4: XSS — búsqueda y mensajes sin escape
// ─────────────────────────────────────────────
app.get('/api/search', (req, res) => {
  res.json({ query: req.query.q || '', results: [] });
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
// VULN 5: Command Injection
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
// VULN 7: Path Traversal
// ─────────────────────────────────────────────
app.get('/api/file', (req, res) => {
  const name = req.query.name || 'readme.txt';
  const filePath = path.join('/app/public', name);
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({ file: name, resolved: filePath, content });
  } catch (e) {
    res.status(404).json({ error: e.message, resolved: filePath });
  }
});

// ─────────────────────────────────────────────
// VULN 8: SSRF
// ─────────────────────────────────────────────
app.post('/api/fetch', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url requerida' });
  const client = url.startsWith('https://') ? https : http;
  try {
    const reqOut = client.get(url, { timeout: 5000 }, (response) => {
      let data = '';
      response.on('data', chunk => { data += chunk; });
      response.on('end', () => res.json({ status: response.statusCode, headers: response.headers, body: data.substring(0, 3000), flag: 'FLAG{ssrf_internal_access}' }));
    });
    reqOut.on('error', err => res.status(500).json({ error: err.message }));
    reqOut.on('timeout', () => { reqOut.destroy(); res.status(408).json({ error: 'Timeout' }); });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 9: JWT débil / alg:none
// ─────────────────────────────────────────────
app.post('/api/token', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (err || !results.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = results[0];
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    res.json({ token, hint: 'Secreto débil: "secret". Intenta cambiar alg a "none".' });
  });
});

app.get('/api/admin/flag', (req, res) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authorization: Bearer <token>' });
  try {
    const parts = token.split('.');
    if (parts.length < 2) return res.status(400).json({ error: 'Token malformado' });
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const decoded = header.alg === 'none'
      ? JSON.parse(Buffer.from(parts[1], 'base64').toString())
      : jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: `Rol '${decoded.role}' insuficiente` });
    res.json({ success: true, flag: 'FLAG{jwt_alg_none_pwned}', user: decoded });
  } catch (e) {
    res.status(401).json({ error: 'Token inválido: ' + e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 10: Broken Access Control
// ─────────────────────────────────────────────
app.get('/api/admin/users', (req, res) => {
  if (req.query.role !== 'admin') return res.status(403).json({ error: 'Necesitas ?role=admin' });
  db.query('SELECT id, username, email, role, secret FROM users', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ flag: 'FLAG{bac_admin_bypass}', users: results });
  });
});

// ─────────────────────────────────────────────
// VULN 11: Mass Assignment
// ─────────────────────────────────────────────
app.put('/api/profile', (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'id requerido' });
  const fields = { ...req.body };
  delete fields.id;
  if (!Object.keys(fields).length) return res.status(400).json({ error: 'Sin campos' });
  const cols = Object.keys(fields).map(f => `\`${f}\` = ?`).join(', ');
  db.query(`UPDATE users SET ${cols} WHERE id = ?`, [...Object.values(fields), Number(id)], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    const escalated = 'role' in fields;
    res.json({ success: true, updated: fields, flag: escalated ? 'FLAG{mass_assign_privesc}' : undefined, note: escalated ? `Rol cambiado a '${fields.role}'` : undefined });
  });
});

// ─────────────────────────────────────────────
// VULN 12: Open Redirect
// ─────────────────────────────────────────────
app.get('/api/redirect', (req, res) => {
  if (!req.query.url) return res.status(400).json({ error: 'url requerida' });
  res.redirect(302, req.query.url);
});

// ─────────────────────────────────────────────
// VULN 13: Prototype Pollution
// ─────────────────────────────────────────────
function deepMergeVuln(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] !== null && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      deepMergeVuln(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

app.post('/api/merge', (req, res) => {
  const base = {};
  deepMergeVuln(base, req.body);
  const polluted = ({}).polluted;
  if (polluted !== undefined) { try { delete Object.prototype.polluted; } catch (_) {} }
  res.json({ merged: base, polluted, flag: polluted !== undefined ? 'FLAG{prototype_pollution_pwned}' : undefined, note: polluted !== undefined ? `Object.prototype.polluted = "${polluted}"` : 'Prueba con {"__proto__":{"polluted":"PWNED"}}' });
});

// ─────────────────────────────────────────────
// VULN 14: XXE
// ─────────────────────────────────────────────
app.post('/api/xml', (req, res) => {
  const xmlInput = req.body.xml || '<root></root>';
  const systemMatch = xmlInput.match(/SYSTEM\s+["']([^"']+)["']/);
  if (systemMatch) {
    try {
      const content = fs.readFileSync(systemMatch[1], 'utf8');
      return res.json({ flag: 'FLAG{xxe_file_read_success}', entity_resolved: content.substring(0, 1000), file: systemMatch[1] });
    } catch (e) {
      return res.status(500).json({ error: `No se pudo leer '${systemMatch[1]}': ${e.message}` });
    }
  }
  xml2js.parseString(xmlInput, { explicitArray: false }, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ parsed: result });
  });
});

// ─────────────────────────────────────────────
// VULN 15: SSTI (EJS)
// ─────────────────────────────────────────────
app.post('/api/render', (req, res) => {
  const template = req.body.template || 'Hola <%= user %>!';
  try {
    const output = ejs.render(template, { user: 'guest' });
    res.json({ output, flag: /require|execSync|exec|spawn/i.test(template) ? 'FLAG{ssti_rce_via_ejs}' : undefined });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 16: Insecure Deserialization
// ─────────────────────────────────────────────
app.post('/api/decode', (req, res) => {
  try {
    const raw = Buffer.from(req.body.data || '', 'base64').toString('utf8');
    const obj = JSON.parse(raw, (key, value) => {
      if (typeof value === 'string' && value.startsWith('_FUNC_:')) return eval(value.slice(7));
      return value;
    });
    res.json({ result: obj, flag: raw.includes('_FUNC_:') ? 'FLAG{insecure_deserialize_rce}' : undefined });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 17: File Upload RCE — sin validación de tipo
// ─────────────────────────────────────────────
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sin archivo' });
  // VULNERABLE: acepta cualquier extensión sin validar
  res.json({
    success: true,
    filename: req.file.originalname,
    path: `/uploads/${req.file.originalname}`,
    hint: 'Sube un .js y luego accede a /api/exec?file=tu_archivo.js para ejecutarlo',
  });
});

app.get('/api/exec', (req, res) => {
  const file = req.query.file;
  if (!file) return res.status(400).json({ error: 'file requerido' });
  // VULNERABLE: ejecuta archivos .js subidos por el usuario
  const filePath = path.join('/app/uploads', file);
  try {
    delete require.cache[require.resolve(filePath)];
    const result = require(filePath);
    res.json({ executed: file, result: String(result), flag: 'FLAG{file_upload_rce}' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 18: Race Condition — cupón de un solo uso
// ─────────────────────────────────────────────
app.post('/api/coupon/redeem', (req, res) => {
  const { code, user_id } = req.body;
  // VULNERABLE: check-then-act sin transacción atómica
  db.query('SELECT * FROM coupons WHERE code = ? AND used = 0', [code], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!results.length) return res.status(400).json({ error: 'Cupón no válido o ya usado' });
    const coupon = results[0];
    // Simula tiempo de procesamiento (ventana de race condition)
    setTimeout(() => {
      db.query('UPDATE coupons SET used = 1, used_by = ?, used_at = NOW() WHERE id = ?', [user_id, coupon.id], (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true, discount: coupon.discount, flag: 'FLAG{race_condition_double_spend}', note: 'Cupón aplicado — si llegaste antes del UPDATE, usaste el mismo cupón dos veces' });
      });
    }, 50);
  });
});

app.post('/api/coupon/reset', (req, res) => {
  db.query("UPDATE coupons SET used = 0, used_by = NULL, used_at = NULL WHERE code = 'RACE100'", () => {
    res.json({ success: true, message: 'Cupón RACE100 reiniciado' });
  });
});

// ─────────────────────────────────────────────
// VULN 19: CORS Misconfiguration — origen reflejado + credentials
// ─────────────────────────────────────────────
app.get('/api/cors/secret', (req, res) => {
  const origin = req.headers.origin || 'null';
  // VULNERABLE: refleja cualquier origen y permite credenciales
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({ flag: 'FLAG{cors_credential_theft}', secret_token: 'tok_admin_8f3k2j', user: 'admin', private_data: 'balance: $9,999' });
});

app.options('/api/cors/secret', (req, res) => {
  const origin = req.headers.origin || 'null';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.sendStatus(204);
});

// ─────────────────────────────────────────────
// VULN 20: Password Reset inseguro — token predecible sin expiración
// ─────────────────────────────────────────────
app.post('/api/reset-request', (req, res) => {
  const { email } = req.body;
  const host = req.headers['host']; // VULNERABLE para VULN 28 (Host Header Injection)
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!results.length) return res.json({ sent: false, message: 'Si el email existe, recibirás un link' });
    // VULNERABLE: token = timestamp en hex (predecible)
    const token = Math.floor(Date.now() / 1000).toString(16);
    const resetLink = `http://${host}/api/reset-confirm?token=${token}&email=${email}`;
    db.query('INSERT INTO password_resets (user_id, token) VALUES (?, ?)', [results[0].id, token], () => {});
    res.json({ sent: true, token, resetLink, note: 'Token = timestamp Unix en hex. En producción esto va por email.' });
  });
});

app.post('/api/reset-confirm', (req, res) => {
  const { token, email, new_password } = req.body;
  // VULNERABLE: no verifica expiración del token
  db.query('SELECT pr.*, u.email FROM password_resets pr JOIN users u ON pr.user_id = u.id WHERE pr.token = ? AND u.email = ?',
    [token, email], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!results.length) return res.status(400).json({ error: 'Token inválido' });
      db.query('UPDATE users SET password = ? WHERE email = ?', [new_password, email], () => {});
      db.query('DELETE FROM password_resets WHERE token = ?', [token], () => {});
      res.json({ success: true, flag: 'FLAG{reset_token_predictable}', message: 'Contraseña cambiada' });
    });
});

// ─────────────────────────────────────────────
// VULN 21: ReDoS — regex catastrófica
// ─────────────────────────────────────────────
app.post('/api/validate-email', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email requerido' });
  const start = Date.now();
  // VULNERABLE: regex con backtracking exponencial
  const pattern = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/;
  const valid = pattern.test(email);
  const elapsed = Date.now() - start;
  res.json({ valid, elapsed_ms: elapsed, flag: elapsed > 100 ? 'FLAG{redos_event_loop_blocked}' : undefined, note: elapsed > 100 ? `El event loop de Node.js estuvo bloqueado ${elapsed}ms` : 'Prueba con el payload de ReDoS' });
});

// ─────────────────────────────────────────────
// VULN 22: Business Logic — cantidad negativa
// ─────────────────────────────────────────────
app.post('/api/order', (req, res) => {
  const { product_id, quantity, user_id } = req.body;
  if (!product_id || quantity === undefined) return res.status(400).json({ error: 'product_id y quantity requeridos' });
  db.query('SELECT * FROM products WHERE id = ?', [product_id], (err, results) => {
    if (err || !results.length) return res.status(404).json({ error: 'Producto no encontrado' });
    const product = results[0];
    // VULNERABLE: no valida que quantity sea positivo
    const total = product.price * quantity;
    db.query('INSERT INTO orders (user_id, product_id, quantity, unit_price, total) VALUES (?, ?, ?, ?, ?)',
      [user_id || 2, product_id, quantity, product.price, total], (err2, result) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({
          order_id: result.insertId,
          product: product.name,
          quantity,
          unit_price: product.price,
          total,
          flag: total < 0 ? 'FLAG{business_logic_negative_charge}' : undefined,
          note: total < 0 ? `Total negativo: $${total.toFixed(2)} — el sistema te debe dinero` : `Total: $${total.toFixed(2)}`,
        });
      });
  });
});

app.get('/api/products', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ─────────────────────────────────────────────
// VULN 23: CRLF Injection — inyección de headers
// ─────────────────────────────────────────────
app.get('/api/set-lang', (req, res) => {
  const lang = req.query.lang || 'es';
  // VULNERABLE: inyecta el valor directamente en el header Set-Cookie
  res.setHeader('Set-Cookie', `lang=${lang}; Path=/`);
  res.json({ lang, note: 'Cookie lang establecida. Prueba inyectar \\r\\n para añadir headers extra.' });
});

// ─────────────────────────────────────────────
// VULN 24: Clickjacking — sin X-Frame-Options
// ─────────────────────────────────────────────
app.get('/api/headers-check', (req, res) => {
  // VULNERABLE: sin cabeceras de seguridad
  res.json({
    missing: {
      'X-Frame-Options': 'AUSENTE — permite clickjacking vía iframe',
      'Content-Security-Policy': 'AUSENTE — sin protección XSS/injection',
      'X-Content-Type-Options': 'AUSENTE — permite MIME sniffing',
      'Strict-Transport-Security': 'AUSENTE — sin HSTS',
      'Referrer-Policy': 'AUSENTE',
      'Permissions-Policy': 'AUSENTE',
    },
    flag: 'FLAG{missing_security_headers}',
    fix: 'Usar helmet.js: app.use(helmet())',
  });
});

// ─────────────────────────────────────────────
// VULN 25: Account Enumeration — mensajes diferentes
// ─────────────────────────────────────────────
app.post('/api/check-login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!results.length) {
      // VULNERABLE: revela que el usuario no existe
      return res.json({ success: false, message: 'Usuario no encontrado', flag: 'FLAG{account_enumeration}' });
    }
    if (results[0].password !== password) {
      // VULNERABLE: revela que el usuario SÍ existe
      return res.json({ success: false, message: 'Contraseña incorrecta', flag: 'FLAG{account_enumeration}' });
    }
    res.json({ success: true, message: `Bienvenido ${username}` });
  });
});

// ─────────────────────────────────────────────
// VULN 26: Verb Tampering — GET evita auth de POST
// ─────────────────────────────────────────────
app.all('/api/admin/secret-action', (req, res) => {
  // VULNERABLE: solo verifica auth cuando el método es POST
  if (req.method === 'POST') {
    const apikey = req.headers['x-api-key'];
    if (apikey !== 'admin-super-secret') {
      return res.status(403).json({ error: 'API key inválida. Header: X-Api-Key: admin-super-secret' });
    }
  }
  // Los GET requests bypasean completamente la verificación
  res.json({ success: true, flag: 'FLAG{verb_tampering_bypass}', method: req.method, action: 'Acción admin ejecutada sin autenticación via GET' });
});

// ─────────────────────────────────────────────
// VULN 27: Log Injection — newlines en logs
// ─────────────────────────────────────────────
app.post('/api/log', (req, res) => {
  const { message } = req.body;
  // VULNERABLE: escribe el mensaje sin sanitizar en los logs del servidor
  const logEntry = `[${new Date().toISOString()}] [USER] ${message}`;
  console.log(logEntry);
  res.json({ logged: true, entry: logEntry, flag: /\n|\r/.test(message) ? 'FLAG{log_injection_fake_entry}' : undefined, note: /\n|\r/.test(message) ? 'Líneas inyectadas en los logs del servidor' : 'Prueba con \\n para inyectar líneas falsas' });
});

// ─────────────────────────────────────────────
// VULN 28: Host Header Injection — password reset poisoning
// ─────────────────────────────────────────────
app.post('/api/reset-poison', (req, res) => {
  const { email } = req.body;
  // Lee el Host header del cliente sin validar
  const host = req.headers['x-forwarded-host'] || req.headers['host'];
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    const token = Math.floor(Date.now() / 1000).toString(16);
    // VULNERABLE: usa el Host header controlado por el atacante
    const resetLink = `http://${host}/reset?token=${token}`;
    const poisoned = host && !host.includes('localhost') && !host.includes('127.0.0.1');
    res.json({
      sent: !!results.length,
      resetLink,
      host_used: host,
      flag: poisoned ? 'FLAG{host_header_injection}' : undefined,
      note: poisoned
        ? `Link envenenado → víctima clickea y el token llega a ${host}`
        : 'Cambia el header Host o añade X-Forwarded-Host: evil.com para envenenar el link',
    });
  });
});

// ─────────────────────────────────────────────
// VULN 29: Second-order SQLi
// ─────────────────────────────────────────────
app.post('/api/update-username', (req, res) => {
  const { user_id, username } = req.body;
  // Fase 1: almacena de forma segura (prepared statement)
  db.query('UPDATE users SET username = ? WHERE id = ?', [username, user_id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, stored: username, note: 'Almacenado con prepared statement — seguro en esta fase' });
  });
});

app.get('/api/greet', (req, res) => {
  const user_id = req.query.id;
  db.query('SELECT username FROM users WHERE id = ?', [user_id], (err, results) => {
    if (err || !results.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const username = results[0].username;
    // Fase 2: VULNERABLE — usa el valor almacenado sin sanitizar en nueva query
    const query = `SELECT id, username, email, role, secret FROM users WHERE username = '${username}'`;
    db.query(query, (err2, results2) => {
      if (err2) return res.json({ error: err2.sqlMessage, query, flag: 'FLAG{second_order_sqli}' });
      res.json({ greeting: `Hola, ${username}!`, query, results: results2, flag: results2.length > 1 || username.includes("'") ? 'FLAG{second_order_sqli}' : undefined });
    });
  });
});

// ─────────────────────────────────────────────
// VULN 30: Blind SQLi — solo devuelve true/false
// ─────────────────────────────────────────────
app.get('/api/user-exists', (req, res) => {
  const username = req.query.username || '';
  // VULNERABLE: concatenación — permite extraer datos caracter por caracter
  const query = `SELECT COUNT(*) as cnt FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
    if (err) return res.json({ exists: false, error: err.sqlMessage, flag: 'FLAG{blind_sqli}' });
    const exists = results[0].cnt > 0;
    res.json({ exists, flag: username.includes("'") ? 'FLAG{blind_sqli}' : undefined });
  });
});

// ─────────────────────────────────────────────
// VULN 31: Session Fixation
// ─────────────────────────────────────────────
app.post('/api/session/login', (req, res) => {
  const { username, password, sid } = req.body;
  db.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (err || !results.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = results[0];
    // VULNERABLE: acepta session ID propuesto por el cliente
    const sessionId = sid || crypto.randomBytes(16).toString('hex');
    sessions[sessionId] = { userId: user.id, username: user.username, role: user.role };
    res.json({ success: true, session_id: sessionId, user: user.username, note: sid ? 'Usó SID del cliente — fijación de sesión posible' : 'SID generado aleatoriamente' });
  });
});

app.get('/api/session/profile', (req, res) => {
  const sid = req.headers['x-session-id'] || req.query.sid;
  const session = sessions[sid];
  if (!session) return res.status(401).json({ error: 'Sesión no encontrada. Header: X-Session-ID: <sid>' });
  res.json({ session, flag: 'FLAG{session_fixation_hijack}' });
});

// ─────────────────────────────────────────────
// VULN 32: JWT Algorithm Confusion (RS256 → HS256)
// ─────────────────────────────────────────────
app.get('/api/rs256/pubkey', (req, res) => {
  res.json({ publicKey: rsaPublicPem, hint: 'Usa esta clave pública como secreto HMAC para forjar un token HS256' });
});

app.post('/api/rs256/token', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (err || !results.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = results[0];
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, rsaPrivate, { algorithm: 'RS256', expiresIn: '1h' });
    res.json({ token, algorithm: 'RS256', publicKey: rsaPublicPem });
  });
});

app.post('/api/rs256/forge', (req, res) => {
  // Endpoint helper: firma con la clave pública como secreto HMAC (simula el ataque del cliente)
  const payload = req.body;
  // VULNERABLE: el servidor mismo puede usarse para crear el token forjado
  const forged = jwt.sign(payload, rsaPublicPem, { algorithm: 'HS256' });
  res.json({ forged_token: forged, note: 'Firmado con la clave pública como secreto HMAC — algoritmo HS256' });
});

app.get('/api/rs256/flag', (req, res) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authorization: Bearer <token>' });
  try {
    // VULNERABLE: acepta tanto RS256 como HS256 — permite confusion attack
    const decoded = jwt.verify(token, rsaPublicPem, { algorithms: ['RS256', 'HS256'] });
    if (decoded.role !== 'admin') return res.status(403).json({ error: `Rol '${decoded.role}' insuficiente. Necesitas role:admin` });
    res.json({ success: true, flag: 'FLAG{jwt_algorithm_confusion}', decoded });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 33: 2FA Brute Force — sin rate limiting
// ─────────────────────────────────────────────
app.post('/api/2fa/setup', (req, res) => {
  const { user_id } = req.body;
  // PIN de 4 dígitos (0000-9999)
  const pin = String(Math.floor(Math.random() * 10000)).padStart(4, '0');
  twofa_codes[user_id || '1'] = { pin, attempts: 0 };
  res.json({ user_id: user_id || '1', note: 'PIN de 4 dígitos generado (0000-9999). Sin límite de intentos.' });
});

app.post('/api/2fa/verify', (req, res) => {
  const { user_id, code } = req.body;
  const data = twofa_codes[user_id || '1'];
  if (!data) return res.status(400).json({ error: 'Haz setup primero' });
  // VULNERABLE: sin rate limiting, sin lockout, sin bloqueo
  data.attempts++;
  if (code === data.pin) {
    res.json({ success: true, flag: 'FLAG{2fa_brute_force}', pin: data.pin, attempts: data.attempts });
  } else {
    res.json({ success: false, message: 'PIN incorrecto', attempts_so_far: data.attempts });
  }
});

// ─────────────────────────────────────────────
// VULN 34: OAuth — parámetro state ausente
// ─────────────────────────────────────────────
app.get('/api/oauth/authorize', (req, res) => {
  const { redirect_uri, state } = req.query;
  const code = crypto.randomBytes(8).toString('hex');
  oauth_codes[code] = { redirect_uri, state: state || null, used: false };
  res.json({ code, state_echoed: state || null, redirect_uri, note: state ? 'State presente — CSRF protegido' : 'VULNERABLE: sin state → CSRF en OAuth posible' });
});

app.get('/api/oauth/callback', (req, res) => {
  const { code, state } = req.query;
  const authData = oauth_codes[code];
  if (!authData || authData.used) return res.status(400).json({ error: 'Código inválido o ya usado' });
  authData.used = true;
  // VULNERABLE: no verifica que el state del callback coincide con el del authorize
  const poisoned = !authData.state;
  res.json({
    success: true,
    access_token: 'oauth_' + crypto.randomBytes(8).toString('hex'),
    state_verified: !!authData.state,
    flag: poisoned ? 'FLAG{oauth_state_missing}' : undefined,
    note: poisoned ? 'OAuth completado sin state — un atacante pudo haber iniciado este flujo (CSRF)' : 'State verificado correctamente',
  });
});

// ─────────────────────────────────────────────
// VULN 35: Insecure Math.random() — PRNG débil
// ─────────────────────────────────────────────
app.post('/api/prng/token', (req, res) => {
  const { user_id } = req.body;
  // VULNERABLE: Math.random() no es criptográficamente seguro
  const token = Math.random().toString(36).substring(2, 10);
  prng_tokens[user_id || '1'] = token;
  res.json({ token, entropy_bits: Math.log2(36 ** 8).toFixed(1), note: 'Generado con Math.random() — predecible y baja entropía vs crypto.randomBytes(32)' });
});

app.get('/api/prng/samples', (req, res) => {
  // Genera 10 tokens consecutivos para mostrar el patrón
  const samples = Array.from({ length: 10 }, () => Math.random().toString(36).substring(2, 10));
  res.json({ samples, flag: 'FLAG{weak_prng_math_random}', note: 'V8 usa xorshift128+ — con suficientes muestras el estado interno es recuperable' });
});

// ─────────────────────────────────────────────
// VULN 36: Timing Attack — comparación no constante
// ─────────────────────────────────────────────
const TIMING_SECRET = 'vulnlab2024';

app.post('/api/timing/check', (req, res) => {
  const { guess } = req.body || {};
  const start = process.hrtime.bigint();
  // VULNERABLE: early-exit revela cuántos chars coinciden por tiempo
  let match = true;
  for (let i = 0; i < TIMING_SECRET.length; i++) {
    if (!guess || guess[i] !== TIMING_SECRET[i]) { match = false; break; }
    // 1ms artificial por caracter correcto (exagerado para hacerlo visible)
    const t = Date.now(); while (Date.now() - t < 1) {}
  }
  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
  res.json({ match, elapsed_ms: elapsed.toFixed(2), hint: 'A más caracteres correctos, más tarda la respuesta', flag: match ? 'FLAG{timing_attack_secret_found}' : undefined });
});

// ─────────────────────────────────────────────
// VULN 37: Email Header Injection
// ─────────────────────────────────────────────
app.post('/api/contact', (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.status(400).json({ error: 'Campos requeridos: name, email, message' });
  // VULNERABLE: email y name van directo a los headers sin sanitizar
  const headers = `From: ${email}\r\nTo: admin@corp.com\r\nSubject: Contacto de ${name}`;
  const injected = /[\r\n]/.test(email) || /[\r\n]/.test(name);
  res.json({
    sent: true,
    headers_used: headers,
    flag: injected ? 'FLAG{email_header_injection}' : undefined,
    note: injected ? 'Headers inyectados — Bcc, From, etc. pueden añadirse' : 'Prueba con \\r\\n en el campo email para inyectar headers',
  });
});

// ─────────────────────────────────────────────
// VULN 38: HTTP Parameter Pollution
// ─────────────────────────────────────────────
app.get('/api/items', (req, res) => {
  const id = req.query.id;
  // Con ?id=1&id=admin , Express toma el último valor como array o el primero
  if (Array.isArray(id)) {
    // VULNERABLE: comportamiento impredecible — WAF ve el primero, app usa el último
    const first = id[0];
    const last = id[id.length - 1];
    db.query('SELECT id, username, email, role FROM users WHERE id = ?', [last], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ received_ids: id, waf_sees: first, app_uses: last, result: results[0] || null, flag: 'FLAG{http_param_pollution}' });
    });
  } else {
    db.query('SELECT id, username, email, role FROM users WHERE id = ?', [id], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id, result: results[0] || null, note: 'Prueba con ?id=5&id=1 para ver la contaminación de parámetros' });
    });
  }
});

// ─────────────────────────────────────────────
// VULN 39: Excessive Data Exposure
// ─────────────────────────────────────────────
app.get('/api/users/all', (req, res) => {
  // VULNERABLE: devuelve todos los campos incluyendo password y secret
  db.query('SELECT * FROM users', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ flag: 'FLAG{excessive_data_exposure}', users: results, note: 'Incluye password, secret y campos internos que no deberían exponerse' });
  });
});

// ─────────────────────────────────────────────
// VULN 40: Debug endpoints expuestos
// ─────────────────────────────────────────────
app.get('/api/debug', (req, res) => {
  // VULNERABLE: expone configuración interna y variables de entorno
  res.json({
    flag: 'FLAG{debug_endpoint_exposed}',
    node_version: process.version,
    platform: process.platform,
    env: process.env,
    uptime_s: process.uptime().toFixed(1),
    memory: process.memoryUsage(),
    cwd: process.cwd(),
    pid: process.pid,
    sessions_count: Object.keys(sessions).length,
  });
});

// ─────────────────────────────────────────────
// VULN 41: Stack traces en producción
// ─────────────────────────────────────────────
app.get('/api/crash', (req, res) => {
  const input = req.query.input || '';
  try {
    // VULNERABLE: errores revelan stack trace, rutas del servidor y estructura interna
    const obj = JSON.parse(input);
    const val = obj.a.b.c; // lanza TypeError si la estructura no existe
    res.json({ result: val });
  } catch (e) {
    res.status(500).json({
      error: e.message,
      stack: e.stack,          // VULNERABLE: expone rutas del servidor
      input,
      flag: 'FLAG{stack_trace_disclosure}',
    });
  }
});

// ─────────────────────────────────────────────
// VULN 42: Hash sin sal — MD5 vulnerable a rainbow tables
// ─────────────────────────────────────────────
app.get('/api/hashes', (req, res) => {
  // VULNERABLE: expone hashes MD5 sin sal — crackeables con rainbow tables
  res.json({
    flag: 'FLAG{weak_hash_no_salt}',
    note: 'MD5 sin sal — usa https://crackstation.net para crackearlos',
    hashes: [
      { username: 'admin',  hash: crypto.createHash('md5').update('supersecret123').digest('hex'), algo: 'MD5' },
      { username: 'jsmith', hash: crypto.createHash('md5').update('password123').digest('hex'),    algo: 'MD5' },
      { username: 'victim', hash: crypto.createHash('md5').update('mypassword').digest('hex'),     algo: 'MD5' },
    ],
  });
});

// ─────────────────────────────────────────────
// VULN 43: Cookie flags ausentes — robable via XSS
// ─────────────────────────────────────────────
app.post('/api/cookie-login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (err || !results.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = results[0];
    // VULNERABLE: sin HttpOnly → robable con document.cookie (XSS)
    // VULNERABLE: sin Secure → transmitida en HTTP plano
    // VULNERABLE: sin SameSite → usable en requests CSRF
    res.setHeader('Set-Cookie', `session_id=${user.id}:${user.username}:${user.role}; Path=/`);
    res.json({ success: true, flag: 'FLAG{cookie_missing_flags}', user: user.username, note: 'Cookie sin HttpOnly, Secure ni SameSite' });
  });
});

// ─────────────────────────────────────────────
// VULN 44 & 45: DOM XSS y DOM Clobbering — frontend only (ver HTML)
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// VULN 46: Stored SSRF — URL guardada y fetchada después
// ─────────────────────────────────────────────
app.post('/api/webhook/save', (req, res) => {
  const { id, url } = req.body;
  if (!id || !url) return res.status(400).json({ error: 'id y url requeridos' });
  // VULNERABLE: guarda la URL sin validar destino
  webhooks[id] = url;
  res.json({ saved: true, id, url, note: 'La URL se fetchará cuando se dispare el webhook — SSRF indirecto' });
});

app.post('/api/webhook/trigger', (req, res) => {
  const { id } = req.body;
  const url = webhooks[id];
  if (!url) return res.status(404).json({ error: 'Webhook no encontrado' });
  // VULNERABLE: fetcha URL almacenada — el origen del SSRF no es directo
  const client = url.startsWith('https://') ? https : http;
  try {
    const reqOut = client.get(url, { timeout: 4000 }, (response) => {
      let data = '';
      response.on('data', chunk => { data += chunk; });
      response.on('end', () => res.json({ triggered: true, url, status: response.statusCode, body: data.substring(0, 1000), flag: 'FLAG{stored_ssrf}' }));
    });
    reqOut.on('error', err => res.json({ triggered: true, url, error: err.message, flag: 'FLAG{stored_ssrf}' }));
    reqOut.on('timeout', () => { reqOut.destroy(); res.json({ triggered: true, url, error: 'Timeout', flag: 'FLAG{stored_ssrf}' }); });
  } catch (e) {
    res.json({ triggered: false, error: e.message });
  }
});

// ─────────────────────────────────────────────
// VULN 47: Zip Slip — extracción sin validar paths
// ─────────────────────────────────────────────
app.get('/api/zipslip/malicious', (req, res) => {
  // Genera un ZIP con una entrada de path traversal para el demo
  const zip = new AdmZip();
  zip.addFile('normal.txt', Buffer.from('Archivo normal de prueba'));
  zip.addFile('../../tmp/zipslip_pwned.txt', Buffer.from('FLAG{zip_slip_traversal}\nArchivo escrito fuera del directorio destino'));
  const buffer = zip.toBuffer();
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename=malicious.zip');
  res.send(buffer);
});

app.post('/api/unzip', upload.single('zipfile'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sin archivo zip' });
  const DEST = '/app/uploads/extracted/';
  fs.mkdirSync(DEST, { recursive: true });
  try {
    const zip = new AdmZip(req.file.path);
    const entries = [];
    zip.getEntries().forEach(entry => {
      const destPath = path.join(DEST, entry.entryName);
      // VULNERABLE: no verifica que destPath esté dentro de DEST
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      fs.writeFileSync(destPath, entry.getData());
      const slipped = !destPath.startsWith(DEST);
      entries.push({ entry: entry.entryName, dest: destPath, slipped });
    });
    const hasSlip = entries.some(e => e.slipped);
    res.json({ extracted: entries, flag: hasSlip ? 'FLAG{zip_slip_traversal}' : undefined, note: hasSlip ? 'Archivo escrito fuera del directorio destino' : 'Sin traversal detectado' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Health check
app.get('/api/health', (_, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`VulnLab backend running on :${PORT}`));
