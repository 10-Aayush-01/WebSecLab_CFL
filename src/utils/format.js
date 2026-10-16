'use strict';

/**
 * One timestamp format everywhere: "13 Oct 2026, 14:32:08".
 * Views receive these through app.locals, so a change here changes every page.
 */

const TIMESTAMP_FORMAT = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23'
});

const DATE_FORMAT = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit',
  month: 'short',
  year: 'numeric'
});

/** @param {Date|string|number|null|undefined} value */
function formatTimestamp(value) {
  if (value === null || value === undefined || value === '') return '—';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return TIMESTAMP_FORMAT.format(date);
}

/** @param {Date|string|number|null|undefined} value */
function formatDate(value) {
  if (value === null || value === undefined || value === '') return '—';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return DATE_FORMAT.format(date);
}

/** First 8 characters of a UUID, for compact table cells. */
function shortId(value) {
  return value ? String(value).slice(0, 8) : '—';
}

module.exports = { formatTimestamp, formatDate, shortId };
