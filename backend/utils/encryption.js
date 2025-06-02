const crypto = require('crypto');
const { AES_KEY, AES_IV } = require('../config');

const algorithm = 'aes-256-gcm';

function encrypt(text) {
  const cipher = crypto.createCipheriv(algorithm, AES_KEY, AES_IV);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${encrypted}:${authTag}`;
}

function decrypt(encryptedText) {
  const [encrypted, authTag] = encryptedText.split(':');
  const decipher = crypto.createDecipheriv(algorithm, AES_KEY, AES_IV);
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encrypt, decrypt };
