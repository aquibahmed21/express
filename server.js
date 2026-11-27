const http = require('http');
const express = require('express');
const cors = require('cors');
const { familyRouter, initFamilyStorage } = require('./modules/family');
const { authRouter } = require('./modules/auth');
const { expenseRouter } = require('./modules/expense');
const { usersRouter, loadUsers, verifyToken, setOnlinePhones } = require('./modules/users');
const { setupSignaling, onlinePhones } = require('./modules/signaling');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Allow cross-origin requests (browser app connects from a different origin).
app.use(cors());

// Mounted before the global JSON parser: it brings its own, larger body limits.
app.use(familyRouter);

// Expense Studio backups: brings its own body parsers (small JSON, large raw .db).
app.use(expenseRouter);

app.use(express.json());
app.use(authRouter);
app.use(usersRouter);

app.get('/', (req, res) => {
  res.json({ message: 'Hello from Express', time: new Date().toISOString() });
});

app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// Error handler (last)
app.use((err, req, res, next) => {
  res.status(err.status || err.statusCode || 500).json({ error: err.message || 'Internal Server Error' });
});

async function start() {
  await Promise.all([
    initFamilyStorage().catch(e => console.error('family storage init failed:', e.message)),
    loadUsers().catch(e => console.error('users load failed:', e.message)),
  ]);
  setupSignaling(server, verifyToken);
  setOnlinePhones(onlinePhones);
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

start();
