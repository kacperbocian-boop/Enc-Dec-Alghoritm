const express = require('express');
const router = express.Router();

router.post('/decode', (req, res) => {
  const { text, type } = req.body;

  if (typeof text !== 'string') {
    return res.status(400).json({ error: 'Tekst musi byc tekstem' });
  }

  let decoded;

  try {
    switch (type) {
      case 'base64':
        decoded = Buffer.from(text, 'base64').toString('utf8');
        break;

      case 'hex':
        decoded = Buffer.from(text, 'hex').toString('utf8');
        break;

      case 'url':
        decoded = decodeURIComponent(text);
        break;

      default:
        return res.status(400).json({
          error: 'Nieobslugiwany typ kodowania'
        });
    }

    res.json({ text, type, decoded });

  } catch {
    res.status(400).json({ error: 'Zakodowany tekst jest niepoprawny' });
  }
});

module.exports = router;