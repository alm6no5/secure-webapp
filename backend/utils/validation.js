const validator = require('validator');
const escapeHtml = require('escape-html');

function isValidEmail(email) {
  return validator.isEmail(email);
}

function isValidPassword(password) {
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{8,}$/;
  return passwordRegex.test(password);
}

function sanitizeInput(input) {
  return escapeHtml(input);
}

module.exports = { isValidEmail, isValidPassword, sanitizeInput };
