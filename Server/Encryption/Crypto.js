const crypto = require('node:crypto');
const sodium = require('libsodium-wrappers');

const AEAD_ALGORITHMS = {
  'aes-256-gcm': { keyBytes: 32, nonceBytes: 12, mode: 'gcm' },
  'aes-256-ccm': { keyBytes: 32, nonceBytes: 12, mode: 'ccm' },
  'aria-256-gcm': { keyBytes: 32, nonceBytes: 12, mode: 'gcm' },
  'aria-256-ccm': { keyBytes: 32, nonceBytes: 12, mode: 'ccm' },
};

const TAG_BYTES = 16;
const RSA_ALGORITHMS = {
  'rsa-oaep-2048': 2048,
  'rsa-oaep-3072': 3072,
};

function rsaOptions(key) {
  return {
    key,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256',
  };
}

function encryptRsaHybrid(text, publicKeyPem, algorithm) {
  const modulusLength = RSA_ALGORITHMS[algorithm];
  if (!modulusLength) throw new Error('Nieobslugiwany algorytm');

  const publicKey = crypto.createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== 'rsa' || publicKey.asymmetricKeyDetails.modulusLength !== modulusLength) {
    throw new Error(`Uzyj klucza publicznego RSA ${modulusLength}`);
  }

  const sessionKey = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, nonce);
  const plaintext = Buffer.from(text, 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return {
    encrypted: encrypted.toString('hex'),
    nonce: nonce.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
    wrappedKey: crypto.publicEncrypt(rsaOptions(publicKey), sessionKey).toString('base64'),
  };
}

function decryptRsaHybrid(encryptedHex, privateKeyPem, nonceHex, authTagHex, algorithm, wrappedKey) {
  const modulusLength = RSA_ALGORITHMS[algorithm];
  if (!modulusLength) throw new Error('Nieobslugiwany algorytm');

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== 'rsa' || privateKey.asymmetricKeyDetails.modulusLength !== modulusLength) {
    throw new Error(`Uzyj klucza prywatnego RSA ${modulusLength}`);
  }
  if (typeof wrappedKey !== 'string' || !wrappedKey) throw new Error('Brak klucza RSA do odszyfrowania');

  const sessionKey = crypto.privateDecrypt(rsaOptions(privateKey), Buffer.from(wrappedKey, 'base64'));
  validateLength(sessionKey, 32, 'Wrapped key');
  const nonce = fromHex(nonceHex, 'Nonce');
  const authTag = fromHex(authTagHex, 'Authentication tag');
  const ciphertext = fromHex(encryptedHex, 'Encrypted data');
  validateLength(nonce, 12, 'Nonce');
  validateLength(authTag, TAG_BYTES, 'Authentication tag');

  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function fromHex(value, name) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) {
    throw new Error(`Niepoprawny zapis HEX dla ${name}`);
  }

  return Buffer.from(value, 'hex');
}

function validateLength(value, expected, name) {
  if (value.length !== expected) {
    throw new Error(`Niepoprawna dlugosc ${name} wymagane ${expected} bajtow`);
  }
}

async function encrypt(text, keyHex, algorithm) {
  if (RSA_ALGORITHMS[algorithm]) return encryptRsaHybrid(text, keyHex, algorithm);

  const key = fromHex(keyHex, 'Key');
  const plaintext = Buffer.from(text, 'utf8');

  if (algorithm === '3des-cbc-hmac-sha256') {
    validateLength(key, 56, 'Key');
    const nonce = crypto.randomBytes(8);
    const cipher = crypto.createCipheriv('des-ede3-cbc', key.subarray(0, 24), nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = crypto.createHmac('sha256', key.subarray(24))
      .update(nonce)
      .update(encrypted)
      .digest();
    return { encrypted: encrypted.toString('hex'), nonce: nonce.toString('hex'), authTag: authTag.toString('hex') };
  }

  if (algorithm === 'xsalsa20-poly1305') {
    await sodium.ready;
    validateLength(key, sodium.crypto_secretbox_KEYBYTES, 'Key');
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const combined = Buffer.from(sodium.crypto_secretbox_easy(plaintext, nonce, key));
    return {
      encrypted: combined.subarray(TAG_BYTES).toString('hex'),
      nonce: Buffer.from(nonce).toString('hex'),
      authTag: combined.subarray(0, TAG_BYTES).toString('hex'),
    };
  }

  if (algorithm === 'chacha20-poly1305' || algorithm === 'xchacha20-poly1305') {
    await sodium.ready;
    validateLength(key, 32, 'Key');

    const nonceLength = algorithm === 'chacha20-poly1305'
      ? sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
      : sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const nonce = sodium.randombytes_buf(nonceLength);
    const combined = algorithm === 'chacha20-poly1305'
      ? sodium.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key)
      : sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key);
    const combinedBuffer = Buffer.from(combined);

    return {
      encrypted: combinedBuffer.subarray(0, -TAG_BYTES).toString('hex'),
      nonce: Buffer.from(nonce).toString('hex'),
      authTag: combinedBuffer.subarray(-TAG_BYTES).toString('hex'),
    };
  }

  const spec = AEAD_ALGORITHMS[algorithm];
  if (!spec) throw new Error('Nieobslugiwany algorytm');
  validateLength(key, spec.keyBytes, 'Key');

  const nonce = crypto.randomBytes(spec.nonceBytes);
  const cipher = crypto.createCipheriv(algorithm, key, nonce, { authTagLength: TAG_BYTES });
  if (spec.mode === 'ccm') {
    cipher.setAAD(Buffer.alloc(0), { plaintextLength: plaintext.length });
  }

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    encrypted: ciphertext.toString('hex'),
    nonce: nonce.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
  };
}

async function decrypt(encryptedHex, keyHex, nonceHex, authTagHex, algorithm, wrappedKey) {
  if (RSA_ALGORITHMS[algorithm]) {
    return decryptRsaHybrid(encryptedHex, keyHex, nonceHex, authTagHex, algorithm, wrappedKey);
  }

  const key = fromHex(keyHex, 'Key');
  let ciphertext = fromHex(encryptedHex, 'Encrypted data');
  const nonce = fromHex(nonceHex, 'Nonce');

  if (algorithm === '3des-cbc-hmac-sha256') {
    validateLength(key, 56, 'Key');
    validateLength(nonce, 8, 'Nonce');
    const authTag = fromHex(authTagHex, 'Authentication tag');
    validateLength(authTag, 32, 'Authentication tag');
    const expectedTag = crypto.createHmac('sha256', key.subarray(24))
      .update(nonce)
      .update(ciphertext)
      .digest();
    if (!crypto.timingSafeEqual(authTag, expectedTag)) throw new Error('Niepoprawne dane');

    const decipher = crypto.createDecipheriv('des-ede3-cbc', key.subarray(0, 24), nonce);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  }

  if (algorithm === 'xsalsa20-poly1305') {
    await sodium.ready;
    validateLength(key, sodium.crypto_secretbox_KEYBYTES, 'Key');
    validateLength(nonce, sodium.crypto_secretbox_NONCEBYTES, 'Nonce');
    let authTag;
    if (authTagHex) {
      authTag = fromHex(authTagHex, 'Authentication tag');
    } else {
      if (ciphertext.length < TAG_BYTES) throw new Error('Niepoprawne dane');
      authTag = ciphertext.subarray(0, TAG_BYTES);
      ciphertext = ciphertext.subarray(TAG_BYTES);
    }
    validateLength(authTag, TAG_BYTES, 'Authentication tag');
    const combined = Buffer.concat([authTag, ciphertext]);
    return sodium.to_string(sodium.crypto_secretbox_open_easy(combined, nonce, key));
  }

  if (algorithm === 'chacha20-poly1305' || algorithm === 'xchacha20-poly1305') {
    await sodium.ready;
    validateLength(key, 32, 'Key');
    validateLength(nonce, algorithm === 'chacha20-poly1305' ? 12 : 24, 'Nonce');
    let authTag;
    if (authTagHex) {
      authTag = fromHex(authTagHex, 'Authentication tag');
    } else {
      if (ciphertext.length < TAG_BYTES) throw new Error('Niepoprawne dane');
      authTag = ciphertext.subarray(-TAG_BYTES);
      ciphertext = ciphertext.subarray(0, -TAG_BYTES);
    }
    validateLength(authTag, TAG_BYTES, 'Authentication tag');
    const combined = Buffer.concat([ciphertext, authTag]);
    const plaintext = algorithm === 'chacha20-poly1305'
      ? sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, combined, null, nonce, key)
      : sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, combined, null, nonce, key);
    return sodium.to_string(plaintext);
  }

  const spec = AEAD_ALGORITHMS[algorithm];
  if (!spec) throw new Error('Nieobslugiwany algorytm');
  const authTag = fromHex(authTagHex, 'Authentication tag');
  validateLength(authTag, TAG_BYTES, 'Authentication tag');
  validateLength(key, spec.keyBytes, 'Key');
  validateLength(nonce, spec.nonceBytes, 'Nonce');

  const decipher = crypto.createDecipheriv(algorithm, key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAuthTag(authTag);
  if (spec.mode === 'ccm') {
    decipher.setAAD(Buffer.alloc(0), { plaintextLength: ciphertext.length });
  }

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };