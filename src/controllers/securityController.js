'use strict';

/**
 * ADMIN security events table with type/severity/result filters, a search box
 * and pagination (contract §6).
 *
 * Every filter value is whitelisted inside eventService before it reaches SQL,
 * and the search term is always bound as a parameter.
 */

const eventService = require('../services/eventService');
const { ALL_RULES } = require('../security/detectors');

/** GET /security/events */
async function showEvents(req, res, next) {
  const filters = {
    attackType: req.query.type,
    severity: req.query.severity,
    result: req.query.result,
    search: req.query.search,
    page: req.query.page
  };

  try {
    const { rows, total, page, pages } = await eventService.listEvents(filters);

    return res.render('security/events', {
      title: 'Security Events',
      pageTitle: 'Security Events',
      purpose: 'Every detected attempt against the three labs, newest first.',
      rows,
      total,
      page,
      pages,
      filters: {
        type: filters.attackType || '',
        severity: filters.severity || '',
        result: filters.result || '',
        search: filters.search || ''
      },
      options: {
        types: eventService.ATTACK_TYPES,
        severities: eventService.SEVERITIES,
        results: eventService.RESULTS
      },
      rules: ALL_RULES
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = { showEvents };
