'use strict';

/**
 * One-command database bootstrap (contract §1).
 *
 *   npm run db:reset
 *
 * 1. Connects as ADMIN_DATABASE_URL (superuser, used only here).
 * 2. Creates / updates the two roles declared in DATABASE_URL and
 *    LAB_DATABASE_URL, so the credentials always match .env.
 * 3. Drops and recreates the target database owned by the application role.
 * 4. Applies database/schema.sql, then database/seed.js (runtime-hashed
 *    passwords), then database/seed.sql (products, documents, comments).
 *
 * Flags:
 *   --keep-database   do not drop the database; just re-apply schema + seeds
 *   --seed-only       apply seeds only (keeps existing tables and rows)
 */

const fs = require('fs');
const path = require('path');
const { Client, Pool } = require('pg');

const env = require('../src/config/env');
const { seedUsers } = require('./seed');

const SCHEMA_FILE = path.join(__dirname, 'schema.sql');
const SEED_FILE = path.join(__dirname, 'seed.sql');

const args = process.argv.slice(2);
const KEEP_DATABASE = args.includes('--keep-database');
const SEED_ONLY = args.includes('--seed-only');

/** Parses a postgres:// URL into the pieces the bootstrap needs. */
function parseUrl(raw, label) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${label} is not a valid postgres:// URL.`);
  }
  const database = decodeURIComponent(url.pathname.replace(/^\//, ''));
  if (!database) throw new Error(`${label} must include a database name.`);
  return {
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    host: url.hostname,
    port: Number(url.port || 5432),
    database,
    url: raw
  };
}

/** Quotes an identifier for safe interpolation into DDL. */
const ident = (value) => `"${String(value).replace(/"/g, '""')}"`;
/** Quotes a string literal for safe interpolation into DDL. */
const literal = (value) => `'${String(value).replace(/'/g, "''")}'`;

/** Creates or updates a login role so it matches the URL in .env. */
async function ensureRole(client, { user, password }) {
  const exists = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [user]);
  if (exists.rowCount === 0) {
    await client.query(`CREATE ROLE ${ident(user)} LOGIN PASSWORD ${literal(password)}`);
    console.log(`  created role ${user}`);
  } else {
    await client.query(`ALTER ROLE ${ident(user)} LOGIN PASSWORD ${literal(password)}`);
    console.log(`  role ${user} already existed — password synced with .env`);
  }
}

/** Ensures the database exists, is owned by the app role and is empty. */
async function ensureDatabase(admin, app, database) {
  const found = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [database]);

  if (found.rowCount > 0 && KEEP_DATABASE) {
    console.log(`  database ${database} kept as is`);
    return;
  }

  if (found.rowCount > 0) {
    // Dropping requires exclusive access; terminate anything else connected.
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [database]
    );
    await admin.query(`DROP DATABASE ${ident(database)}`);
    console.log(`  dropped existing database ${database}`);
  }

  await admin.query(`CREATE DATABASE ${ident(database)} OWNER ${ident(app.user)}`);
  console.log(`  created database ${database} owned by ${app.user}`);
}

/** Executes a multi-statement .sql file over a dedicated client. */
async function runSqlFile(connectionString, file, label) {
  const client = new Client({ connectionString });
  await client.connect();
  try {
    await client.query(fs.readFileSync(file, 'utf8'));
    console.log(`  applied ${label}`);
  } finally {
    await client.end();
  }
}

async function main() {
  const app = parseUrl(env.databaseUrl, 'DATABASE_URL');
  const lab = parseUrl(env.labDatabaseUrl, 'LAB_DATABASE_URL');

  if (lab.database !== app.database) {
    throw new Error('LAB_DATABASE_URL must point at the same database as DATABASE_URL.');
  }
  if (lab.user === app.user) {
    console.warn(
      '  warning: LAB_DATABASE_URL uses the same role as DATABASE_URL — ' +
        'least-privilege isolation is lost.'
    );
  }

  if (!SEED_ONLY) {
    if (!env.adminDatabaseUrl) {
      throw new Error(
        'ADMIN_DATABASE_URL is required for a full reset (it creates roles and the database). ' +
          'Use --seed-only to skip it.'
      );
    }

    const admin = new Client({ connectionString: env.adminDatabaseUrl });
    await admin.connect();
    try {
      console.log('Roles:');
      await ensureRole(admin, app);
      await ensureRole(admin, lab);
      console.log('Database:');
      await ensureDatabase(admin, app, app.database);
    } finally {
      await admin.end();
    }

    console.log('Schema:');
    await runSqlFile(env.databaseUrl, SCHEMA_FILE, 'database/schema.sql');
  }

  const pool = new Pool({ connectionString: env.databaseUrl, max: 2 });
  try {
    console.log('Seed data:');
    const count = await seedUsers(pool);
    console.log(`  seeded ${count} demo accounts (runtime-hashed passwords)`);
  } finally {
    await pool.end();
  }

  await runSqlFile(env.databaseUrl, SEED_FILE, 'database/seed.sql');

  // Guard the isolation contract: without this grant the SAFE-mode gap closes
  // silently and the "hidden data" demo stops working.
  const verify = new Pool({ connectionString: env.databaseUrl, max: 2 });
  try {
    await verify.query('GRANT USAGE ON SCHEMA public TO lab_reader');
    await verify.query('GRANT SELECT ON products TO lab_reader');
  } finally {
    await verify.end();
  }

  console.log('\nDatabase ready. Next: npm run db:seed (seeds only) or npm run dev.');
}

main().catch((err) => {
  console.error('\ndb:reset failed:', err.message);
  process.exitCode = 1;
});
