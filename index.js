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
const HOTP = (K, C) => {
  const Truncate = data => data.readUInt32BE();
  const hmac = crypto.createHmac('sha1', K);
  hmac.update(C.toString());
  return Truncate(hmac.digest()) & 0x7FFFFFFF;
};

module.exports = {
  HOTP,
  TOTP
};