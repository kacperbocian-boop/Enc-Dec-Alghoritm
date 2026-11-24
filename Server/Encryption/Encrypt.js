const express = require('express');
const { encrypt } = require('./Crypto');
const router = express.Router();

router.post('/encrypt', async (req, res) => {
  const { text, key, algorithm } = req.body;

  if (typeof text !== 'string' || !key || !algorithm) {
    return res.status(400).json({ error: 'Brakuje wymaganych danych' });
  }

  try {
    const result = await encrypt(text, key, algorithm);

    res.json({
      algorithm,
      ...result,
    });

  } catch {
    res.status(400).json({ error: 'Nie udalo sie zaszyfrowac danych sprawdz klucz i algorytm' });
  }
});

module.exports = router;