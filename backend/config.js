require('dotenv').config();

module.exports = {
  PORT: process.env.PORT || 5000,
  MONGO_URI: process.env.MONGO_URI || 'mongodb+srv://alm6no5pc1:GEZ2004%40%5Czaid@cluster.upihmpx.mongodb.net/',

  JWT_SECRET: process.env.JWT_SECRET || "rF>{7;m354Hk'9/}&?E`p!",

  // تحويل مفاتيح AES من hex string إلى Buffer
  AES_KEY: process.env.AES_KEY ? Buffer.from(process.env.AES_KEY, 'hex') :
           Buffer.from('3719ea5057f047269a72811fa65f9ba4047e581f386bbe1be30508eb930af999', 'hex'),

  AES_IV: process.env.AES_IV ? Buffer.from(process.env.AES_IV, 'hex') :
          Buffer.from('f0e1cab25c91cceaf969a13e3eb8041a', 'hex')
};
