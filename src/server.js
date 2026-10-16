'use strict';

/**
 * Entry point: npm start / npm run dev.
 * Keeps the process alive on unexpected async failures — an educational lab must
 * stay up even when a detector or a log write goes wrong.
 */

const app = require('./app');
const env = require('./config/env');
const { pool, labPool } = require('./config/db');
const { ensureExportsDir } = require('./security/evidence');

ensureExportsDir();

const server = app.listen(env.port, () => {
  // Report the port actually bound, never the requested one.
  const address = server.address();
  const boundPort = address && typeof address === 'object' ? address.port : env.port;
  const url = `http://localhost:${boundPort}`;
  console.log('');
  console.log('  WebSecLab — attack detection, prevention and forensic analysis');
  console.log(`  running at   ${url}`);
  console.log(`  environment  ${env.nodeEnv}`);
  console.log(`  evidence dir ${env.exportsDir}`);
  console.log('');
  console.log('  Educational use only — local lab environment.');
  console.log('');
});

/** Closes the listener and both pools. */
function shutdown(signal) {
  console.log(`\n${signal} received — shutting down.`);
  server.close(() => {
    Promise.allSettled([pool.end(), labPool.end()]).finally(() => process.exit(0));
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  console.error('[process] unhandled promise rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[process] uncaught exception:', err);
});
