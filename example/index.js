const { HOTP, TOTP, generateKey } = require('..');

console.log(HOTP('K', '100'));

// console.log(TOTP('secret s'));
// const key = generateKey();
// const code = TOTP(key);

// console.log(code);