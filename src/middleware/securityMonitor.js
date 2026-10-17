'use strict';

/**
 * Security monitor (contract §2).
 *
 * Mounted on /labs/* only. It records every monitored lab request and, when a
 * controller left a labContext behind, runs detection + risk scoring and writes
 * the security event.
 *
 * WHY `res.on('finish')`: detection needs the OUTCOME, and the outcome is only
 * known after the controller has responded. `finish` therefore cannot alter the
 * response — blocking happens in the controller, logging happens here.
 *
 * Every await is wrapped: an async failure inside the monitor must never crash
 * the app or block the response (acceptance test §15/13).
 */

const { detectForLab } = require('../security/detectors');
const outcomeModel = require('../security/outcomeModel');
const riskCalculator = require('../security/riskCalculator');
const { mapResult } = require('../security/resultMapper');
const { buildRequestData, truncate } = require('../security/sanitizer');
const securityLogger = require('../security/securityLogger');

/** The parameter that carries the tested input, per lab. */
const LAB_PARAMETERS = Object.freeze({ SQLI: 'q', XSS: 'comment', IDOR: 'id' });

/**
 * The handshake controllers use before responding (contract §2).
 *
 * @param {import('express').Response} res
 * @param {{lab: 'SQLI'|'XSS'|'IDOR', payload: string|null, resourceId: number|null,
 *          ownerId: number|null, outcome: 'NORMAL'|'EXECUTED_UNSAFE'|'BLOCKED'|'NEUTRALIZED',
 *          basis?: 'MODE'|'RESIDUAL_RISK'}} context
 */
function markLabContext(res, context) {
  res.locals.labContext = {
    lab: context.lab,
    payload: context.payload === undefined ? null : context.payload,
    resourceId: context.resourceId === undefined ? null : context.resourceId,
    ownerId: context.ownerId === undefined ? null : context.ownerId,
    outcome: context.outcome,
    // Which model decided the outcome. Controllers that cannot be affected by
    // the residual-risk model leave it out and it defaults to MODE.
    basis: context.basis || outcomeModel.BASES.MODE
  };
}

/** Express middleware: schedules the audit write when the response finishes. */
function securityMonitor(req, res, next) {
  res.on('finish', () => {
    void recordLabRequest(req, res);
  });
  return next();
}

/**
 * Writes monitored_requests, then the security event when a rule matched.
 * Never throws — problems are logged and the app carries on.
 */
async function recordLabRequest(req, res) {
  try {
    const securityMode = res.locals.securityMode === 'VULNERABLE' ? 'VULNERABLE' : 'SAFE';
    const user = res.locals.user || null;
    const statusCode = res.statusCode;
    const endpoint =
      truncate(`${req.baseUrl || ''}${req.path || ''}`) || truncate(req.originalUrl) || 'unknown';

    let monitoredRequestId = null;
    try {
      monitoredRequestId = await securityLogger.recordMonitoredRequest({
        userId: user ? user.id : null,
        httpMethod: req.method,
        endpoint,
        securityMode,
        statusCode
      });
    } catch (err) {
      console.error('[monitor] could not record monitored request:', err.message);
    }

    const labContext = res.locals.labContext;
    if (!labContext) return;

    const detection = detectForLab(labContext.lab, {
      payload: labContext.payload,
      userId: user ? user.id : null,
      ownerId: labContext.ownerId,
      resourceId: labContext.resourceId
    });

    // A legitimate search or your own document is monitored but not an event.
    if (!detection.detected) return;

    const result = mapResult(labContext.outcome);
    const risk = riskCalculator.calculate({
      attackType: detection.attackType,
      result,
      authenticated: Boolean(user)
    });

    const requestData = buildRequestData({
      parameter: LAB_PARAMETERS[labContext.lab] || null,
      payload: labContext.payload,
      resourceId: labContext.resourceId,
      userAgent: req.get('user-agent') || null,
      // Recorded on every event so an audit row always says whether the mode or
      // the residual-risk draw produced it (see src/security/outcomeModel.js).
      outcomeBasis: labContext.basis
    });

    const event = await securityLogger.createSecurityEvent({
      userId: user ? user.id : null,
      sourceIp: req.ip || null,
      httpMethod: req.method,
      endpoint,
      attackType: detection.attackType,
      severity: risk.severity,
      riskScore: risk.score,
      matchedRule: detection.matchedRule,
      requestData,
      securityMode,
      result,
      statusCode
    });

    if (monitoredRequestId !== null) {
      await securityLogger.flagMonitoredRequest(monitoredRequestId);
    }

    console.log(
      `[monitor] ${detection.attackType} ${result} score=${risk.score} ${risk.severity} ` +
        `rule=${detection.matchedRule} mode=${securityMode} basis=${labContext.basis} ` +
        `incident=${event.event_uuid}`
    );
  } catch (err) {
    // Last line of defence: the monitor is never allowed to take the app down.
    console.error('[securityMonitor] failed to record security event:', err.message);
  }
}

module.exports = { securityMonitor, markLabContext, LAB_PARAMETERS };
