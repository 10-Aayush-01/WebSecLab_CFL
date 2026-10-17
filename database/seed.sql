-- ============================================================================
-- WebSecLab seed data (non-user tables). Runs AFTER database/seed.js, which
-- creates the user accounts with runtime-hashed passwords.
-- Idempotent: safe to run repeatedly (npm run db:seed).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Products — the SQL Injection lab data source.
-- Three rows have is_released = FALSE: a normal search never shows them, but a
-- tautology payload in VULNERABLE mode does ("retrieving hidden data").
-- ---------------------------------------------------------------------------
INSERT INTO products (name, description, price, category, is_released) VALUES
  ('AeroBook 14 Laptop',            '14-inch ultrabook, 16 GB RAM, 512 GB SSD.',        74999.00, 'Laptops',     TRUE),
  ('AeroBook Pro 16 Laptop',        '16-inch workstation laptop, 32 GB RAM.',          129999.00, 'Laptops',     TRUE),
  ('PixelView 27 Monitor',          '27-inch 1440p IPS display with USB-C input.',       21499.00, 'Displays',    TRUE),
  ('QuietKeys Mechanical Keyboard', 'Tactile switches, hot-swappable keycaps.',           6499.00, 'Accessories', TRUE),
  ('NodeNest USB-C Dock',           '11-port dock with gigabit ethernet.',                8999.00, 'Accessories', TRUE),
  ('SoundWell ANC Headphones',      'Over-ear noise cancelling headphones.',             15999.00, 'Audio',       TRUE),
  ('SwiftDrive 1TB NVMe SSD',       'PCIe 4.0 internal solid state drive.',               9499.00, 'Storage',     TRUE),
  ('BeamLink Wi-Fi 6 Router',       'Dual-band router, four gigabit ports.',              5499.00, 'Networking',  TRUE),
  ('TagIt Bluetooth Tracker',       'Keyring tracker with 6-month battery.',              2499.00, 'Accessories', TRUE),
  ('Falcon Pre-Release Laptop',     'INTERNAL: unreleased prototype, do not publish.',  154999.00, 'Laptops',     FALSE),
  ('Helios Internal Test Server',   'INTERNAL: staging server build, unreleased.',      289000.00, 'Servers',     FALSE),
  ('Aurora Prototype Display',      'INTERNAL: pre-release panel, embargoed.',           39999.00, 'Displays',    FALSE)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Documents — the IDOR lab data source. Sequential ids on purpose.
-- Owners are resolved by email so this stays correct after a re-seed.
-- ---------------------------------------------------------------------------
INSERT INTO user_documents (owner_id, title, content)
SELECT u.id, d.title, d.content
FROM (VALUES
  ('alice@webseclab.local', 'Q3 Client Proposal',    'Draft proposal: scope, deliverables and timeline for the Q3 client engagement.'),
  ('alice@webseclab.local', 'Personal Notes',        'Private working notes. Not for sharing outside this account.'),
  ('alice@webseclab.local', 'Travel Itinerary',      'Flight 6E-204 on 21 Oct, hotel confirmation 88-3412.'),
  ('alice@webseclab.local', 'Lab Report Draft',      'Sections 1-4 of the WebSecLab report, awaiting review.'),
  ('bob@webseclab.local',   'Team Roster',           'Shift roster for the support team, revised every Monday.'),
  ('bob@webseclab.local',   'Budget Worksheet',      'Equipment budget for the current quarter. Confidential.'),
  ('bob@webseclab.local',   'Vendor Contacts',       'Primary contacts for hardware vendors and service partners.')
) AS d(email, title, content)
JOIN users u ON u.email = d.email
WHERE NOT EXISTS (
  SELECT 1 FROM user_documents x WHERE x.owner_id = u.id AND x.title = d.title
);

-- ---------------------------------------------------------------------------
-- Comments — the XSS lab data source (3 sample comments, harmless content).
-- ---------------------------------------------------------------------------
INSERT INTO comments (user_id, comment)
SELECT u.id, c.body
FROM (VALUES
  ('alice@webseclab.local', 'The dashboard loads much faster after the last update.'),
  ('bob@webseclab.local',   'Would be nice to be able to sort the events table by severity.'),
  ('alice@webseclab.local', 'Tested the search box today, works as expected.')
) AS c(email, body)
JOIN users u ON u.email = c.email
WHERE NOT EXISTS (
  SELECT 1 FROM comments x WHERE x.user_id = u.id AND x.comment = c.body
);
