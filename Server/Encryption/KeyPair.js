const crypto = require('node:crypto');
const express = require('express');
const router = express.Router();

const RSA_ALGORITHMS = {
  'rsa-oaep-2048': 2048,
  'rsa-oaep-3072': 3072,
};

router.post('/keypair', (req, res) => {
  const modulusLength = RSA_ALGORITHMS[req.body?.algorithm];
  if (!modulusLength) {
    return res.status(400).json({ error: 'Nieobslugiwany algorytm RSA' });
  }

  try {
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    return res.json({ algorithm: req.body.algorithm, ...keyPair });
  } catch {
    return res.status(500).json({ error: 'Nie udalo sie wygenerowac pary RSA' });
  }
});

module.exports = router;