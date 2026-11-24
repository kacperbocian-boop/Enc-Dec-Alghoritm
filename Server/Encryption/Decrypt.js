const express = require('express');
const { decrypt } = require('./Crypto');
const router = express.Router();

router.post('/decrypt', async (req, res) => {
  const { encrypted, key, nonce, authTag, algorithm, wrappedKey } = req.body;

  if (typeof encrypted !== 'string' || !key || !nonce || !algorithm) {
    return res.status(400).json({ error: 'Brakuje wymaganych danych' });
  }

  try {
    const plaintext = await decrypt(encrypted, key, nonce, authTag, algorithm, wrappedKey);

    res.json({
      algorithm,
      decrypted: plaintext,
    });

  } catch (error) {
    res.status(400).json({
      error: error.message === 'Nieobslugiwany algorytm'
        ? error.message
        : 'Nie udalo sie odszyfrowac danych sprawdz klucz i szyfrogram',
    });
  }
});

module.exports = router;