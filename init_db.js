const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Directory where user and ticket data will be stored. The server will
// read from and write to these files. If the directory does not exist
// it will be created automatically. Each file will contain JSON data.
const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
const ticketsFile = path.join(dataDir, 'tickets.json');

// Default users mirrored from the original front‑end. These users
// include names, roles, modules and permissions. Passwords are
// supplied in plain text here but will be stored as salted SHA‑256
// hashes in the users.json file. A salt is generated per user to
// protect against rainbow table attacks. In production you would
// derive the hash with a stronger function like scrypt or pbkdf2.
const USERS = {
  daniel: {
    password: 'admin123',
    name: 'Daniel',
    role: 'admin',
    modules: ['all'],
    permissions: ['calendar:write'],
  },
  techniker: {
    password: 'labor123',
    name: 'Technik-Team',
    role: 'labor',
    modules: ['calendar', 'orders'],
    permissions: ['calendar:write'],
  },
  empfang: {
    password: 'welcome123',
    name: 'Empfang',
    role: 'frontdesk',
    // Front‑desk staff should be able to submit support tickets and view the
    // calendar. Therefore the `support` module is added to the list of
    // allowed modules in addition to `forms` and `calendar`.
    modules: ['forms', 'calendar', 'support'],
    permissions: ['calendar:write'],
  },
  finanzen: {
    password: 'reports123',
    name: 'Finanzen',
    role: 'finance',
    modules: ['analytics'],
    permissions: [],
  },
  orthodont: {
    password: 'Material',
    name: 'Dr. Can',
    role: 'management',
    modules: ['all'],
    permissions: ['calendar:write'],
    greeting: 'Herzlich willkommen Simon Can',
  },
  charlottenburg: {
    password: 'cahrlottenburg20!',
    name: 'Rezeption Charlottenburg',
    role: 'frontdesk',
    modules: ['forms', 'orders', 'support', 'calendar'],
    permissions: ['calendar:write'],
  },
  techniker1: {
    password: 'cblab',
    name: 'Labor Charlottenburg',
    role: 'labor',
    modules: ['calendar'],
    permissions: [],
  },
  zb: {
    password: 'zb-team2024',
    name: 'ZB Team',
    role: 'zb',
    modules: ['calendar'],
    permissions: ['calendar:write'],
  },
};

// Ensure the data directory exists
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize the users file. If it already exists and contains data
// this script will not overwrite it. Otherwise it generates salted
// password hashes for the predefined users and writes them to the file.
function initUsers() {
  if (fs.existsSync(usersFile)) {
    try {
      const existing = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
      if (Array.isArray(existing) && existing.length > 0) {
        console.log('Users file already populated. Skipping user creation.');
        return;
      }
    } catch {
      // Fall through to recreate file
    }
  }
  const records = [];
  let idCounter = 1;
  for (const username of Object.keys(USERS)) {
    const entry = USERS[username];
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256').update(entry.password + salt).digest('hex');
    records.push({
      id: idCounter++,
      username: username.toLowerCase(),
      salt,
      hash,
      name: entry.name,
      role: entry.role,
      modules: entry.modules,
      permissions: entry.permissions,
      greeting: entry.greeting || null,
    });
  }
  fs.writeFileSync(usersFile, JSON.stringify(records, null, 2), 'utf8');
  console.log('Default users written to', usersFile);
}

// Initialize the tickets file if it does not exist. It will start as an
// empty array. Tickets will be appended by the server at runtime.
function initTickets() {
  if (!fs.existsSync(ticketsFile)) {
    fs.writeFileSync(ticketsFile, JSON.stringify([], null, 2), 'utf8');
    console.log('Created empty tickets file at', ticketsFile);
  }
}

initUsers();
initTickets();