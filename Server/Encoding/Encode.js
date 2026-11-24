const express = require('express');
const router = express.Router();

router.post('/encode', (req, res) => {
  const { text, type } = req.body;

  if (typeof text !== 'string') {
    return res.status(400).json({ error: 'Tekst musi byc tekstem' });
  }

  let encoded;

  switch (type) {
    case 'base64':
      encoded = Buffer.from(text, 'utf8').toString('base64');
      break;

    case 'hex':
      encoded = Buffer.from(text, 'utf8').toString('hex');
      break;

    case 'url':
      encoded = encodeURIComponent(text);
      break;

    default:
      return res.status(400).json({
        error: 'Nieobslugiwany typ kodowania',
        supported: ['base64', 'hex', 'url']
      });
  }

  res.json({ text, type, encoded });
});

module.exports = router;