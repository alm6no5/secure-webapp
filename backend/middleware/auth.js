const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.cookies.token;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden: insufficient rights' });
    }
    next();
  };
}

module.exports = { authenticateToken, authorizeRoles };
