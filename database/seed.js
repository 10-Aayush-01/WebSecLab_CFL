'use strict';

/**
 * User accounts are seeded here (not in seed.sql) so that password hashes are
 * produced at runtime by bcrypt — no hash is ever hard-coded in the repository.
 *
 * Demo credentials (local lab only, also documented in README.md):
 *   ADMIN  admin@webseclab.local  Admin-Lab-Demo-2026
 *   USER   alice@webseclab.local  User-Lab-Demo-2026
 *   USER   bob@webseclab.local    User-Lab-Demo-2026
 *
 * Override with SEED_ADMIN_PASSWORD / SEED_USER_PASSWORD in .env.
 */

const env = require('../src/config/env');
const { hashPassword } = require('../src/security/password');

const DEMO_ACCOUNTS = [
  {
    name: 'Lab Administrator',
    email: 'admin@webseclab.local',
    password: env.seedAdminPassword,
    role: 'ADMIN'
  },
  {
    name: 'Alice Anderson',
    email: 'alice@webseclab.local',
    password: env.seedUserPassword,
    role: 'USER'
  },
  {
    name: 'Bob Brown',
    email: 'bob@webseclab.local',
    password: env.seedUserPassword,
    role: 'USER'
  }
];

/**
 * Upserts the three demo accounts. Re-running resets their passwords, so the
 * credentials above always work (documented in README).
 *
 * @param {import('pg').Pool} pool a connected application pool
 * @returns {Promise<number>} number of accounts written
 */
async function seedUsers(pool) {
  for (const account of DEMO_ACCOUNTS) {
    const passwordHash = await hashPassword(account.password);
    await pool.query(
      `INSERT INTO users (name, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email) DO UPDATE
         SET name = EXCLUDED.name,
             password_hash = EXCLUDED.password_hash,
             role = EXCLUDED.role`,
      [account.name, account.email, passwordHash, account.role]
    );
  }
  return DEMO_ACCOUNTS.length;
}

module.exports = { seedUsers, DEMO_ACCOUNTS };

/* istanbul ignore next — CLI entry point */
if (require.main === module) {
  const { pool } = require('../src/config/db');

  seedUsers(pool)
    .then(async (count) => {
      console.log(`Seeded ${count} demo accounts with runtime-hashed passwords.`);
      await pool.end();
    })
    .catch(async (err) => {
      console.error('Seeding users failed:', err.message);
      await pool.end().catch(() => {});
      process.exitCode = 1;
    });
}
