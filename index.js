const crypto = require('crypto');
/**
 * Time-based One-time Password algorithm
 * https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm
 */
const TOTP = K => {
  const { floor } = Math;
  const unixtime = time => time / 1000;
  const TS = 30;
  const T0 = new Date(0);
  const T1 = new Date();
  const TC = floor((unixtime(T1) - unixtime(T0)) / TS);
  return HOTP(K, TC);
};
/**
 * HMAC-based One-time Password algorithm
 * https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm#Definition
 * @param K be a secret key
 * @param C be a counter
 */
const HOTP = (K, C, L = 6) => {
  return (Truncate(HMAC(K, C)) & 0x7FFFFFFF).toString().slice(0, L);
};
/**
 * Truncate
 * @param {*} data 
 */
const Truncate = data => data.readUInt32BE();
/**
 * HMAC
 * @param {*} K 
 * @param {*} C 
 */
const HMAC = (K, C) => {
  const hmac = crypto.createHmac('sha1', K);
  hmac.update(C.toString());
  return hmac.digest();
};
/**
 * base-32 encoding
 * @param {*} length 
 */
const generateKey = (length = 20) => {
  let r = '';
  do {
    const b = crypto.randomBytes(6);
    const h = b.toString('hex');
    const n = parseInt(h, 16);
    const t = n.toString(32);
    r += t;
  } while (r.length < length)
  return r.slice(0, length);
};

module.exports = {
  HOTP,
  TOTP,
  generateKey,
};