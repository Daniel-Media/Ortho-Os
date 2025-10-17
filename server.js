// Simplified HTTP server for Ortho OS using only built‑in Node.js modules.
//
// This server provides endpoints for authentication and ticket management
// without relying on external packages. User and ticket data are stored
// in JSON files under the ./data directory. Authentication tokens are
// generated using HMAC‑SHA256 and are verified on protected routes.

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Optional: Nodemailer for sending email notifications. In production you
// should install the `nodemailer` package via `npm install nodemailer`.
// The server will attempt to require it; if unavailable the sendEmail
// function will fall back to logging notifications to the console.
let nodemailer;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  nodemailer = null;
  console.warn('Nodemailer is not installed. Email notifications will be logged to the console.');
}

// Configure an email transporter when nodemailer is available. The
// configuration is read from environment variables. For example:
// EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS. When no transport is
// configured the server will not actually send emails but will log the
// messages instead. See README for more details.
let emailTransport = null;
if (nodemailer) {
  const host = process.env.EMAIL_HOST;
  const port = process.env.EMAIL_PORT;
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS;
  if (host && port && user && pass) {
    emailTransport = nodemailer.createTransport({
      host,
      port: Number(port),
      secure: Number(port) === 465,
      auth: { user, pass },
    });
  }
}

/**
 * Send an email notification. If nodemailer is not configured this
 * function will simply log the email details to the console. When
 * configured, the message will be sent asynchronously and errors
 * will be logged. The `to` parameter may be a single email address
 * or an array. Subject and text should be plain strings. No HTML
 * content is sent for compatibility with simple clients.
 *
 * @param {string|string[]} to Recipient email address(es)
 * @param {string} subject Email subject line
 * @param {string} text Plain text body content
 */
async function sendEmail(to, subject, text) {
  if (emailTransport) {
    try {
      await emailTransport.sendMail({ from: process.env.EMAIL_FROM || 'no‑reply@orthoos.local', to, subject, text });
      console.log('Email sent to', to, 'subject:', subject);
    } catch (err) {
      console.warn('Failed to send email:', err.message);
    }
  } else {
    // Fall back to logging
    console.log('Notification (no mail transport): to=%s subject=%s text=%s', to, subject, text);
  }
}

// Data directory and files
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TICKETS_FILE = path.join(DATA_DIR, 'tickets.json');

// Secret used for signing and verifying tokens. In production this
// should be stored securely and loaded via environment variables.
const SECRET = 'orthos-hmac-secret-change-me';

// Load JSON from disk or return a default value. If the file cannot be
// read or parsed the default is returned.
function readJson(file, defaultValue) {
  try {
    const content = fs.readFileSync(file, 'utf8');
    return JSON.parse(content);
  } catch (err) {
    return defaultValue;
  }
}

// Write JSON data to disk. Uses 2‑space indentation for readability.
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

// Load users and tickets into memory. These variables are kept up to
// date whenever the respective files are written to.
let users = readJson(USERS_FILE, []);
let tickets = readJson(TICKETS_FILE, []);

// Helper to sign a payload and produce a JWT‑like token. The header
// specifies HS256 algorithm. The payload is provided by the caller.
function signToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest()
    .toString('base64url');
  return `${data}.${signature}`;
}

// Verify a token and return its payload if valid. If verification fails
// or parsing fails this function returns null. Timing safe comparison
// is used to avoid leaked information about the signature.
function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;
  const expected = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest()
    .toString('base64url');
  // Compare signatures in constant time
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    return payload;
  } catch {
    return null;
  }
}

// Parse the body of a request. Returns an object with fields and files.
// Supports application/json, application/x-www-form-urlencoded and
// multipart/form-data (files saved to uploads folder). Attachments are
// stored in the uploads directory and returned under result.files.
async function parseRequestBody(req) {
  return new Promise((resolve) => {
    const contentType = req.headers['content-type'] || '';
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const buffer = Buffer.concat(chunks);
      if (contentType.startsWith('application/json')) {
        try {
          const json = JSON.parse(buffer.toString());
          resolve({ fields: json, files: {} });
        } catch {
          resolve({ fields: {}, files: {} });
        }
      } else if (contentType.startsWith('application/x-www-form-urlencoded')) {
        const querystring = buffer.toString();
        const fields = {};
        querystring.split('&').forEach((part) => {
          const [key, value] = part.split('=').map(decodeURIComponent);
          if (key) fields[key] = value;
        });
        resolve({ fields, files: {} });
      } else if (contentType.startsWith('multipart/form-data')) {
        const boundaryMatch = contentType.match(/boundary=([^;]+)/);
        const boundary = boundaryMatch ? boundaryMatch[1] : null;
        const result = { fields: {}, files: {} };
        if (!boundary) {
          resolve(result);
          return;
        }
        const raw = buffer.toString('latin1');
        const parts = raw.split(`--${boundary}`);
        for (const part of parts) {
          if (!part || part === '--\r\n' || part === '--') continue;
          const sep = part.indexOf('\r\n\r\n');
          if (sep === -1) continue;
          const rawHeaders = part.slice(0, sep);
          let value = part.slice(sep + 4);
          if (value.endsWith('\r\n')) value = value.slice(0, -2);
          const dispositionMatch = rawHeaders.match(/name="([^"]+)"(?:;\s*filename="([^"]+)")?/i);
          if (!dispositionMatch) continue;
          const name = dispositionMatch[1];
          const filename = dispositionMatch[2];
          if (!filename) {
            result.fields[name] = value;
          } else {
            const uploadsDir = path.join(__dirname, 'uploads');
            if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
            const safeName = Date.now() + '-' + filename.replace(/[^a-zA-Z0-9\.\-_]/g, '_');
            fs.writeFileSync(path.join(uploadsDir, safeName), Buffer.from(value, 'latin1'));
            if (!result.files[name]) result.files[name] = [];
            result.files[name].push(safeName);
          }
        }
        resolve(result);
      } else {
        resolve({ fields: {}, files: {} });
      }
    });
  });
}

// Write updated users or tickets to disk. After writing the in‑memory
// variable is refreshed so that subsequent operations use the latest
// data.
function saveUsers(data) {
  writeJson(USERS_FILE, data);
  users = data;
}
function saveTickets(data) {
  writeJson(TICKETS_FILE, data);
  tickets = data;
}

// Extract the Bearer token from the Authorization header. Returns
// null if no token is provided.
function getTokenFromHeaders(headers) {
  const authHeader = headers['authorization'] || headers['Authorization'];
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
    return parts[1];
  }
  return null;
}

// Send a plain 404 response with JSON error.
function sendNotFound(res) {
  sendJson(res, 404, { error: 'Not found' });
}

// Helper to send a JSON response with a given status code. Sets
// Content-Type and Content-Length headers and ends the response.
function sendJson(res, statusCode, data) {
  const json = JSON.stringify(data);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', Buffer.byteLength(json));
  res.end(json);
}

// The main request handler which routes incoming HTTP requests to
// appropriate functions based on method and path.
async function requestHandler(req, res) {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname || '';

  // --- CORS handling ---
  // Allow cross‑origin requests from any origin. This is important when
  // the frontend is served from a file:// URL or a different domain. We
  // permit common methods and headers. For preflight requests (OPTIONS)
  // we respond immediately with a 204 status.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, HEAD, OPTIONS');
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  // Serve uploaded files statically from /uploads
  if ((req.method === 'GET' || req.method === 'HEAD') && pathname.startsWith('/uploads/')) {
    const filePath = path.join(__dirname, pathname);
    if (filePath.indexOf(path.join(__dirname, 'uploads')) !== 0) {
      // Prevent directory traversal
      return sendNotFound(res);
    }
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const stream = fs.createReadStream(filePath);
      stream.on('open', () => {
        res.statusCode = 200;
        // rudimentary content type detection
        const ext = path.extname(filePath).toLowerCase();
        const typeMap = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.pdf': 'application/pdf' };
        const contentType = typeMap[ext] || 'application/octet-stream';
        res.setHeader('Content-Type', contentType);
        stream.pipe(res);
      });
      stream.on('error', (err) => {
        console.error('Error serving upload:', err);
        sendNotFound(res);
      });
      return;
    }
    return sendNotFound(res);
  }

  // Health check
  if (req.method === 'GET' && pathname === '/api/health') {
    return sendJson(res, 200, { status: 'ok' });
  }
  // HEAD connectivity check for tickets
  if (req.method === 'HEAD' && pathname === '/api/tickets') {
    res.statusCode = 200;
    return res.end();
  }

  // Authentication endpoint
  if (req.method === 'POST' && pathname === '/api/auth/login') {
    const { fields } = await parseRequestBody(req);
    const username = String((fields.username || '')).toLowerCase();
    const password = String(fields.password || '');
    if (!username || !password) {
      return sendJson(res, 400, { error: 'Benutzername und Passwort erforderlich' });
    }
    const user = users.find((u) => u.username === username);
    if (!user) {
      return sendJson(res, 401, { error: 'Ungültiger Benutzername oder Passwort' });
    }
    const hash = crypto.createHash('sha256').update(password + user.salt).digest('hex');
    if (hash !== user.hash) {
      return sendJson(res, 401, { error: 'Ungültiger Benutzername oder Passwort' });
    }
    // Build payload for token (omit sensitive fields)
    const payload = {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
      modules: user.modules,
      permissions: user.permissions,
      greeting: user.greeting || null,
    };
    const token = signToken(payload);
    return sendJson(res, 200, { token, user: payload });
  }

  // Ticket routes
  if (pathname === '/api/tickets') {
    if (req.method === 'GET') {
      // Only admins can view all tickets
      const token = getTokenFromHeaders(req.headers);
      const user = verifyToken(token);
      if (!user) {
        return sendJson(res, 401, { error: 'Authentifizierung erforderlich' });
      }
      if (!user.role || user.role.toLowerCase() !== 'admin') {
        return sendJson(res, 403, { error: 'Nur Administratoren können Tickets einsehen' });
      }
      // Return tickets in reverse order (latest first)
      const sorted = [...tickets].sort((a, b) => {
        const idA = a.id || 0;
        const idB = b.id || 0;
        return idB - idA;
      });
      return sendJson(res, 200, { tickets: sorted });
    }
    if (req.method === 'POST') {
      // Creating a ticket does not require authentication but will record
      // requester information if a valid token is provided.
      const { fields, files } = await parseRequestBody(req);
      const title = String(fields.title || '').trim();
      const description = String(fields.description || '').trim();
      if (!title || !description) {
        return sendJson(res, 400, { error: 'Titel und Beschreibung sind erforderlich' });
      }
      const priority = String(fields.priority || 'medium').toLowerCase();
      const location = fields.location ? String(fields.location).trim() : '';
      const responsible = fields.responsible ? String(fields.responsible).trim() : '';
      const dueDate = fields.dueDate ? String(fields.dueDate).trim() : '';
      const userEmail = fields.userEmail ? String(fields.userEmail).trim() : '';
      const token = getTokenFromHeaders(req.headers);
      const authUser = verifyToken(token);
      const now = new Date().toISOString();
      const newId = tickets.reduce((max, t) => Math.max(max, t.id || 0), 0) + 1;
      const newTicket = {
        id: newId,
        title,
        description,
        priority,
        location: location || null,
        responsible: responsible || null,
        dueDate: dueDate || null,
        status: 'open',
        createdDate: now,
        requesterName: authUser ? authUser.name : fields.requesterName || null,
        requesterRole: authUser ? authUser.role : fields.requesterRole || null,
        attachments: files.attachments || [],
        email: userEmail || null,
      };
      tickets.push(newTicket);
      saveTickets(tickets);
      // Send notification to the admin when a new ticket is created. The
      // recipient address is hard coded but can be configured via the
      // EMAIL_NOTIFY constant or environment variables in the future.
      const adminEmail = process.env.NOTIFY_EMAIL || 'Daniel.media.orthodont@gmail.com';
      const subject = `Neues Ticket: ${title}`;
      let body = `Es wurde ein neues Support‑Ticket erstellt.`;
      body += `\n\nTitel: ${title}`;
      body += `\nBeschreibung: ${description}`;
      if (newTicket.requesterName) body += `\nErstellt von: ${newTicket.requesterName}`;
      if (newTicket.email) body += `\nKontakt: ${newTicket.email}`;
      sendEmail(adminEmail, subject, body);
      return sendJson(res, 201, { message: 'Ticket erstellt' });
    }
  }
  // Update ticket status
  const patchMatch = pathname.match(/^\/api\/tickets\/(\d+)\/status$/);
  if (patchMatch && req.method === 'PATCH') {
    const id = Number(patchMatch[1]);
    const token = getTokenFromHeaders(req.headers);
    const user = verifyToken(token);
    if (!user) {
      return sendJson(res, 401, { error: 'Authentifizierung erforderlich' });
    }
    if (!user.role || user.role.toLowerCase() !== 'admin') {
      return sendJson(res, 403, { error: 'Nur Administratoren können den Ticketstatus ändern' });
    }
    const { fields } = await parseRequestBody(req);
    const newStatus = String(fields.status || '').toLowerCase();
    if (!newStatus) {
      return sendJson(res, 400, { error: 'Neuer Status erforderlich' });
    }
    if (!['open', 'progress', 'closed'].includes(newStatus)) {
      return sendJson(res, 400, { error: 'Ungültiger Statuswert' });
    }
    const ticket = tickets.find((t) => t.id === id);
    if (!ticket) {
      return sendJson(res, 404, { error: 'Ticket nicht gefunden' });
    }
    ticket.status = newStatus;
    saveTickets(tickets);
    // Send completion notification if ticket is closed
    if (newStatus === 'closed') {
      const recipient = ticket.email || null;
      if (recipient) {
        let completionSubject;
        let completionBody;
        // Determine message based on whether a team or single person is referenced
        const isTeam = (ticket.requesterRole || '').toLowerCase().includes('team') || (ticket.requesterName || '').toLowerCase().includes('team');
        if (isTeam) {
          completionSubject = `Euer Ticket #${ticket.id} wurde abgeschlossen`;
          completionBody = `Hallo zusammen,\n\nEuer gemeldetes Ticket mit dem Titel "${ticket.title}" wurde erfolgreich abgeschlossen. Falls ihr weitere Fragen habt oder erneut Unterstützung benötigt, könnt ihr jederzeit ein neues Ticket erstellen.\n\nBeste Grüße,\nEuer Ortho OS Support Team`;
        } else {
          completionSubject = `Dein Ticket #${ticket.id} wurde abgeschlossen`;
          completionBody = `Hallo ${ticket.requesterName || ''},\n\nDein gemeldetes Ticket mit dem Titel "${ticket.title}" wurde erfolgreich abgeschlossen. Solltest du noch Fragen haben oder wieder Hilfe benötigen, kannst du gern ein neues Ticket erstellen.\n\nFreundliche Grüße,\nDein Ortho OS Support Team`;
        }
        sendEmail(recipient, completionSubject, completionBody);
      }
    }
    return sendJson(res, 200, { message: 'Status aktualisiert' });
  }
  // Delete ticket
  const deleteMatch = pathname.match(/^\/api\/tickets\/(\d+)$/);
  if (deleteMatch && req.method === 'DELETE') {
    const id = Number(deleteMatch[1]);
    const token = getTokenFromHeaders(req.headers);
    const user = verifyToken(token);
    if (!user) {
      return sendJson(res, 401, { error: 'Authentifizierung erforderlich' });
    }
    if (!user.role || user.role.toLowerCase() !== 'admin') {
      return sendJson(res, 403, { error: 'Nur Administratoren können Tickets löschen' });
    }
    const index = tickets.findIndex((t) => t.id === id);
    if (index === -1) {
      return sendJson(res, 404, { error: 'Ticket nicht gefunden' });
    }
    const [removed] = tickets.splice(index, 1);
    // Delete attachments from disk
    if (removed.attachments && removed.attachments.length) {
      const uploadsDir = path.join(__dirname, 'uploads');
      removed.attachments.forEach((filename) => {
        const filePath = path.join(uploadsDir, filename);
        fs.unlink(filePath, (err) => {
          if (err) {
            console.warn('Could not delete attachment', filePath, err.message);
          }
        });
      });
    }
    saveTickets(tickets);
    return sendJson(res, 200, { message: 'Ticket gelöscht' });
  }

  // Unknown route
  return sendNotFound(res);
}

// Create HTTP server and start listening
const server = http.createServer((req, res) => {
  requestHandler(req, res).catch((err) => {
    console.error('Unhandled server error:', err);
    sendJson(res, 500, { error: 'Serverfehler' });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});