'use strict';

/**
 * Password hashing wrapper. bcrypt is the primary implementation; if the native
 * build is unavailable on a teammate's machine, swap the require below for
 * 'bcryptjs' — the hash format ($2…) is identical, so nothing else changes.
 *
 * Cost 11 sits inside the required 10–12 band.
 */

const bcrypt = require('bcrypt');

const COST = 11;

/**
 * @param {string} plain
 * @returns {Promise<string>} a $2… hash
 */
const hashPassword = (plain) => bcrypt.hash(plain, COST);

/**
 * Constant-time comparison. Never throws on a malformed stored hash.
 * @param {string} plain
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plain, hash) {
  if (typeof plain !== 'string' || typeof hash !== 'string' || !hash.startsWith('$2')) {
    return false;
  }
  try {
    return await bcrypt.compare(plain, hash);
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword, COST };
