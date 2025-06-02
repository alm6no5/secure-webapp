require('dotenv').config();

if (
  !process.env.MONGO_URI ||
  !process.env.JWT_SECRET ||
  !process.env.AES_KEY ||
  !process.env.AES_IV
) {
  throw new Error('Missing required environment variables. Please check your .env file.');
}

module.exports = {
  PORT: process.env.PORT || 5000,
  
  MONGO_URI: process.env.MONGO_URI,

  JWT_SECRET: process.env.JWT_SECRET,

  // تحويل مفاتيح AES من hex string إلى Buffer
  AES_KEY: Buffer.from(process.env.AES_KEY, 'hex'),

  AES_IV: Buffer.from(process.env.AES_IV, 'hex'),
};
