-- ============================================================================
-- WebSecLab — database schema (frozen contract: docs/CONTRACTS.md §1)
-- Owner: the application role in DATABASE_URL (webseclab_app).
-- Run with: npm run db:reset   (which also creates roles + seed data)
--
-- Do NOT rename tables, columns or enum values: the runtime contract depends
-- on them literally.
-- ============================================================================

BEGIN;

DROP TABLE IF EXISTS incident_actions   CASCADE;
DROP TABLE IF EXISTS security_events    CASCADE;
DROP TABLE IF EXISTS monitored_requests CASCADE;
DROP TABLE IF EXISTS user_documents     CASCADE;
DROP TABLE IF EXISTS comments           CASCADE;
DROP TABLE IF EXISTS products           CASCADE;
DROP TABLE IF EXISTS app_settings       CASCADE;
DROP TABLE IF EXISTS users              CASCADE;

-- ---------------------------------------------------------------------------
-- Accounts
-- ---------------------------------------------------------------------------
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(10) NOT NULL DEFAULT 'USER' CHECK (role IN ('USER','ADMIN')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Global security mode: exactly one row, id = 1
-- ---------------------------------------------------------------------------
CREATE TABLE app_settings (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  security_mode VARCHAR(10) NOT NULL DEFAULT 'SAFE' CHECK (security_mode IN ('VULNERABLE','SAFE')),
  updated_by INT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Lab 1 (SQL Injection) data source. is_released = FALSE rows are the
-- "hidden data" that a tautology payload can expose in VULNERABLE mode.
-- ---------------------------------------------------------------------------
CREATE TABLE products (
  id SERIAL PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  description TEXT,
  price NUMERIC(10,2) NOT NULL,
  category VARCHAR(60) NOT NULL,
  is_released BOOLEAN NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------------------
-- Lab 2 (XSS) data source. Stored raw in both modes; the view decides rendering.
-- ---------------------------------------------------------------------------
CREATE TABLE comments (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  comment TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Lab 3 (IDOR) data source. Sequential ids on purpose (enumeration is the point).
-- ---------------------------------------------------------------------------
CREATE TABLE user_documents (
  id SERIAL PRIMARY KEY,
  owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(150) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Every request that hit /labs/* (feeds "Total Monitored Requests")
-- ---------------------------------------------------------------------------
CREATE TABLE monitored_requests (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id INT REFERENCES users(id) ON DELETE SET NULL,
  http_method VARCHAR(10) NOT NULL,
  endpoint TEXT NOT NULL,
  security_mode VARCHAR(10) NOT NULL,
  status_code INT NOT NULL,
  flagged BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX idx_monitored_time ON monitored_requests (occurred_at DESC);

-- ---------------------------------------------------------------------------
-- Detected security events (the audit record)
-- ---------------------------------------------------------------------------
CREATE TABLE security_events (
  id SERIAL PRIMARY KEY,
  event_uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id INT REFERENCES users(id) ON DELETE SET NULL,
  source_ip VARCHAR(64),
  http_method VARCHAR(10) NOT NULL,
  endpoint TEXT NOT NULL,
  attack_type VARCHAR(20) NOT NULL CHECK (attack_type IN ('SQL_INJECTION','XSS','IDOR')),
  severity VARCHAR(10) NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  risk_score INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  matched_rule VARCHAR(60) NOT NULL,
  request_data JSONB NOT NULL DEFAULT '{}',
  security_mode VARCHAR(10) NOT NULL CHECK (security_mode IN ('VULNERABLE','SAFE')),
  result VARCHAR(12) NOT NULL CHECK (result IN ('DETECTED','SUCCESSFUL','BLOCKED','NEUTRALIZED')),
  status_code INT NOT NULL
);
CREATE INDEX idx_events_type ON security_events (attack_type);
CREATE INDEX idx_events_sev  ON security_events (severity);
CREATE INDEX idx_events_time ON security_events (occurred_at DESC);

-- ---------------------------------------------------------------------------
-- Investigation trail / chain of custody for the forensics module
-- ---------------------------------------------------------------------------
CREATE TABLE incident_actions (
  id SERIAL PRIMARY KEY,
  event_id INT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
  action VARCHAR(30) NOT NULL CHECK (action IN ('INVESTIGATION_OPENED','EVIDENCE_EXPORTED','EVIDENCE_VERIFIED')),
  description TEXT,
  evidence_filename VARCHAR(120),
  evidence_sha256 CHAR(64),
  performed_by INT REFERENCES users(id) ON DELETE SET NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_actions_event ON incident_actions (event_id, occurred_at);

-- ---------------------------------------------------------------------------
-- Single settings row
-- ---------------------------------------------------------------------------
INSERT INTO app_settings (id) VALUES (1);

COMMIT;

-- ---------------------------------------------------------------------------
-- Least-privilege lab role (industry-grade blast-radius control).
-- The VULNERABLE SQLi query runs on this role, so injection cannot reach
-- users / password_hash and cannot write anything.
-- The role itself is created by database/reset.js from LAB_DATABASE_URL.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO lab_reader;
GRANT SELECT ON products TO lab_reader;
