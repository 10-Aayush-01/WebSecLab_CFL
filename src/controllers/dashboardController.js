'use strict';

/**
 * ADMIN dashboard. Every number is a plain count so the acceptance test can
 * compare it against a raw SELECT count(*) (§15/14).
 *
 * The two charts read their series from GET /dashboard/data rather than an
 * inline <script> block: the strict CSP forbids inline script everywhere except
 * the XSS lab, and a JSON endpoint is easier to verify from the command line.
 */

const eventService = require('../services/eventService');

/**
 * Compares the last 24 hours with the 24 before that.
 *
 * Direction is read from a security standpoint: more events is bad, fewer is
 * good. `flat` covers "no change", including 0 → 0.
 *
 * @param {number} current
 * @param {number} previous
 * @returns {{current: number, previous: number, delta: number, direction: 'up'|'down'|'flat'}}
 */
function delta(current, previous) {
  const change = Number(current) - Number(previous);
  return {
    current: Number(current),
    previous: Number(previous),
    delta: change,
    direction: change === 0 ? 'flat' : change > 0 ? 'up' : 'down'
  };
}

/** GET /dashboard */
async function showDashboard(req, res, next) {
  try {
    const [summary, modeSplit, recent] = await Promise.all([
      eventService.getDashboardSummary(),
      eventService.getModeSplit(),
      eventService.getRecentEvents(6)
    ]);

    return res.render('dashboard', {
      title: 'Dashboard',
      pageTitle: 'Dashboard',
      purpose: 'Detection summary for the local lab environment.',
      summary,
      modeSplit,
      recent,
      deltas: {
        events: delta(summary.events_last_24h, summary.events_prev_24h),
        monitored: delta(summary.monitored_last_24h, summary.monitored_prev_24h)
      }
    });
  } catch (err) {
    return next(err);
  }
}

/** GET /dashboard/data — chart series for public/js/dashboard.js */
async function dashboardData(req, res, next) {
  try {
    const [summary, distribution, overTime, modeSplit] = await Promise.all([
      eventService.getDashboardSummary(),
      eventService.getAttackDistribution(),
      eventService.getEventsOverTime(14),
      eventService.getModeSplit()
    ]);

    const modeOf = (mode) => {
      const found = modeSplit.find((row) => row.security_mode === mode);
      return found ? found.total : 0;
    };

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      summary,
      modeSplit: { safe: modeOf('SAFE'), vulnerable: modeOf('VULNERABLE') },
      attackDistribution: {
        labels: distribution.map((row) => row.attack_type),
        values: distribution.map((row) => row.total)
      },
      eventsOverTime: {
        labels: overTime.map((row) => row.day),
        values: overTime.map((row) => row.total)
      }
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = { showDashboard, dashboardData, delta };
