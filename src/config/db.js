'use strict';

/**
 * Two connection pools (contract §1):
 *   pool     — the application role. Full access to the app schema.
 *   labPool  — the least-privilege `lab_reader` role. SELECT on products only.
 *
 * The VULNERABLE SQL Injection query runs on labPool, so a successful
 * injection still cannot read users/password_hash or write anything.
 */

const { Pool } = require('pg');
const env = require('./env');

/** Shared pool options; keeps a runaway lab query from pinning the app. */
const baseOptions = {
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  application_name: 'webseclab'
};

const pool = new Pool({ connectionString: env.databaseUrl, ...baseOptions });

const labPool = new Pool({
  connectionString: env.labDatabaseUrl,
  ...baseOptions,
  max: 4,
  application_name: 'webseclab-lab'
});

// A pool-level error must never take the process down (acceptance test §15/13).
pool.on('error', (err) => {
  console.error('[db] idle client error:', err.message);
});
labPool.on('error', (err) => {
  console.error('[db] idle lab client error:', err.message);
});

/** Runs a parameterized query on the application pool. */
const query = (text, params) => pool.query(text, params);

/** Runs a query on the restricted lab pool (VULNERABLE SQLi only). */
const labQuery = (text, params) => labPool.query(text, params);

/**
 * Runs `fn(client)` inside a transaction, rolling back on any throw.
 * @template T
 * @param {(client: import('pg').PoolClient) => Promise<T>} fn
 * @returns {Promise<T>}
 */
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, labPool, query, labQuery, withTransaction, env };
