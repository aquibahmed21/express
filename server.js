const express = require('express');
const { familyRouter, initFamilyStorage } = require('./modules/family');

const app = express();
const PORT = process.env.PORT || 3000;

// Mounted before the global JSON parser: it brings its own, larger body limits.
// Family history (several families, each with JSON + profile pictures): see modules/family.js
app.use(familyRouter);

app.use(express.json());

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

initFamilyStorage()
  .catch(e => console.error('family storage init failed:', e.message))
  .finally(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server listening on port ${PORT}`);
    });
  });
