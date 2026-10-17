'use strict';

/**
 * Forensic console (contract §6). All routes are ADMIN only.
 *
 * GET  /forensics/verify                     evidence verification page
 * GET  /forensics/:uuid                      investigation page (+ timeline)
 * POST /forensics/:uuid/export               builds + hashes the evidence file
 * GET  /forensics/:uuid/evidence/:filename   downloads those exact bytes
 * POST /forensics/verify                     compares a submitted file's hash
 *
 * The hash is stored outside the evidence file; the file itself is never
 * rewritten. Server filesystem paths are never returned to the client.
 */

const { query } = require('../config/db');
const eventService = require('../services/eventService');
const securityLogger = require('../security/securityLogger');
const { RESULT_LABELS } = require('../security/resultMapper');

const {
  buildEvidence,
  serializeEvidence,
  hashContent,
  evidenceFilename,
  isValidEvidenceFilename,
  writeEvidenceFile,
  readEvidenceFile,
  INTEGRITY_DISCLAIMER,
  mitigationFor
} = require('../security/evidence');

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const isUuid = (value) => typeof value === 'string' && UUID_PATTERN.test(value);
const wantsJson = (req) => req.accepts(['html', 'json']) === 'json';

/** Renders the shared 404 without leaking whether the id existed. */
function notFound(res, message = 'That incident does not exist.') {
  return res.status(404).render('errors/error', {
    status: 404,
    title: 'Incident not found',
    message
  });
}

/**
 * Forensic timeline (contract §6).
 *
 * Honest by design: only two real timestamps exist, so stages 1-4 all carry the
 * same `occurred_at`. The page says so explicitly instead of inventing times.
 */
function buildTimeline(event, actions) {
  const occurredAt = new Date(event.occurred_at);

  const stages = [
    {
      stage: 'Request Received',
      at: occurredAt,
      derived: true,
      note: `${event.http_method} ${event.endpoint} from ${event.source_ip || 'unknown'}`
    },
    {
      stage: 'Suspicious Activity Detected',
      at: occurredAt,
      derived: true,
      note: `Rule ${event.matched_rule} matched the submitted input`
    },
    {
      stage: 'Request Processed / Blocked',
      at: occurredAt,
      derived: true,
      note:
        `HTTP ${event.status_code} — ${RESULT_LABELS[event.result] || event.result} in ${event.security_mode} mode` +
        (event.request_data && event.request_data.outcomeBasis === 'RESIDUAL_RISK'
          ? ' · controls skipped for this attempt by the residual-risk model'
          : '')
    },
    {
      stage: 'Security Event Recorded',
      at: occurredAt,
      derived: true,
      note: 'Row written to security_events'
    }
  ];

  const opened = actions.find((action) => action.action === 'INVESTIGATION_OPENED');
  if (opened) {
    stages.push({
      stage: 'Investigation Opened',
      at: new Date(opened.occurred_at),
      derived: false,
      note: opened.performed_by_email ? `by ${opened.performed_by_email}` : ''
    });
  }

  return stages;
}

/** Loads the incident or sends a 404. Returns null when already handled. */
async function loadIncident(req, res) {
  const uuid = String(req.params.uuid || '');
  if (!isUuid(uuid)) {
    notFound(res, 'That incident reference is not a valid identifier.');
    return null;
  }

  const event = await eventService.getEventByUuid(uuid);
  if (!event) {
    notFound(res);
    return null;
  }

  return event;
}

/** GET /forensics/:uuid */
async function showInvestigation(req, res, next) {
  try {
    const event = await loadIncident(req, res);
    if (!event) return undefined;

    // Idempotent: refreshing the page must not create a second trail entry.
    const existing = await query(
      `SELECT id FROM incident_actions
        WHERE event_id = $1 AND action = 'INVESTIGATION_OPENED'
        LIMIT 1`,
      [event.id]
    );

    if (existing.rowCount === 0) {
      await securityLogger.recordIncidentAction({
        eventId: event.id,
        action: 'INVESTIGATION_OPENED',
        description: 'Investigation opened from the security events table.',
        performedBy: res.locals.user.id
      });
    }

    const [actions, latestExport] = await Promise.all([
      eventService.listIncidentActions(event.id),
      eventService.getLatestExport(event.id)
    ]);

    return res.render('forensics/investigation', {
      title: 'Incident investigation',
      pageTitle: `Incident ${event.event_uuid.slice(0, 8)}`,
      purpose: 'Reconstruct what happened and take the evidence away.',
      event,
      actions,
      latestExport,
      timeline: buildTimeline(event, actions),
      mitigation: mitigationFor(event.attack_type),
      disclaimer: INTEGRITY_DISCLAIMER,
      RESULT_LABELS
    });
  } catch (err) {
    return next(err);
  }
}

/** POST /forensics/:uuid/export */
async function exportEvidence(req, res, next) {
  try {
    const event = await loadIncident(req, res);
    if (!event) return undefined;

    const owner = event.user_id
      ? (await query('SELECT id, role FROM users WHERE id = $1', [event.user_id])).rows[0] || null
      : null;

    const evidence = buildEvidence({
      event,
      user: owner,
      requestData: event.request_data || {}
    });

    const content = serializeEvidence(evidence);
    const filename = evidenceFilename(event.event_uuid);
    const { sha256, bytes } = writeEvidenceFile(filename, content);

    await securityLogger.recordIncidentAction({
      eventId: event.id,
      action: 'EVIDENCE_EXPORTED',
      description: `Evidence package written (${bytes} bytes, sha256 ${sha256}).`,
      evidenceFilename: filename,
      evidenceSha256: sha256,
      performedBy: res.locals.user.id
    });

    console.log(`[forensics] exported ${filename} sha256=${sha256}`);

    if (wantsJson(req)) {
      return res.json({
        filename,
        sha256,
        bytes,
        downloadUrl: `/forensics/${event.event_uuid}/evidence/${filename}`,
        evidence
      });
    }

    res.locals.setFlash('success', `Evidence exported as ${filename}.`);
    return res.redirect(`/forensics/${event.event_uuid}`);
  } catch (err) {
    return next(err);
  }
}

/** GET /forensics/:uuid/evidence/:filename — the exact bytes that were hashed. */
async function downloadEvidence(req, res, next) {
  try {
    const uuid = String(req.params.uuid || '');
    const filename = String(req.params.filename || '');

    if (!isUuid(uuid) || !isValidEvidenceFilename(filename)) {
      return notFound(res, 'That evidence file reference is not valid.');
    }

    const record = await eventService.findExportByFilename(filename);
    if (!record || record.event_uuid !== uuid) {
      return notFound(res, 'No evidence export matches that reference.');
    }

    const content = readEvidenceFile(filename);

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('X-Evidence-SHA256', String(record.evidence_sha256).trim());
    return res.send(content);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      return notFound(res, 'That evidence file is no longer present on disk.');
    }
    return next(err);
  }
}

/** GET /forensics/verify */
async function showVerify(req, res, next) {
  try {
    return res.render('forensics/verify', {
      title: 'Verify evidence',
      pageTitle: 'Verify evidence integrity',
      purpose: 'Re-hash an exported evidence file and compare it with the recorded hash.',
      exports: await eventService.listExports(20),
      disclaimer: INTEGRITY_DISCLAIMER
    });
  } catch (err) {
    return next(err);
  }
}

/** POST /forensics/verify — body: { filename, content } */
async function verifyEvidence(req, res, next) {
  try {
    const filename = String(req.body.filename || '');
    const content = req.body.content;

    if (!isValidEvidenceFilename(filename) || typeof content !== 'string') {
      return res.status(400).json({
        verified: false,
        message: 'Provide evidenceFilename and the file content as text.'
      });
    }

    const record = await eventService.findExportByFilename(filename);
    if (!record) {
      return res.status(404).json({
        verified: false,
        message: 'No exported evidence is recorded under that filename.'
      });
    }

    const actual = hashContent(content);
    const expected = String(record.evidence_sha256).trim();
    const verified = actual === expected;

    await securityLogger.recordIncidentAction({
      eventId: record.event_id,
      action: 'EVIDENCE_VERIFIED',
      description: verified
        ? 'SHA-256 of the submitted file matched the recorded hash.'
        : 'SHA-256 of the submitted file did NOT match the recorded hash.',
      evidenceFilename: filename,
      evidenceSha256: actual,
      performedBy: res.locals.user.id
    });

    return res.json({
      verified,
      filename,
      expected,
      actual,
      message: verified ? 'Evidence integrity verified.' : 'Evidence integrity check failed.'
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  showInvestigation,
  exportEvidence,
  downloadEvidence,
  showVerify,
  verifyEvidence,
  buildTimeline,
  isUuid
};
