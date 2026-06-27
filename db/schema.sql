-- ============================================================
-- BD Hack-Audit — Cloudflare D1 schema (v1)
-- Design principle: respect D1 free-tier 100k rows-written/day.
-- Per-domain CLEAN results are NEVER written. We track scan progress
-- at BATCH granularity (~1000 domains/batch) and write only:
--   (a) findings (the ~1-5% flagged/confirmed) + (b) aggregate counters.
-- ============================================================

-- 1) Master domain registry (append-only, dedup by PK). Harvester inserts here.
CREATE TABLE IF NOT EXISTS domains (
  domain    TEXT PRIMARY KEY,       -- normalized registrable domain (lowercase, no scheme/www/path)
  source    TEXT,                   -- harvest source tag
  bd_score  INTEGER DEFAULT 0,      -- 0-100 is-Bangladesh-business confidence
  business  TEXT,                   -- business name if known
  phone     TEXT,
  batch_id  INTEGER,                -- scan batch this domain belongs to
  pass_no   INTEGER DEFAULT 0,      -- last scan pass that covered it
  added_ts  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_domains_batch  ON domains(batch_id);
CREATE INDEX IF NOT EXISTS idx_domains_source ON domains(source);

-- 2) Scan batches (claimable unit ~1000 domains). One write per status change.
CREATE TABLE IF NOT EXISTS batches (
  batch_id     INTEGER PRIMARY KEY,
  pass_no      INTEGER DEFAULT 1,
  domain_count INTEGER DEFAULT 0,
  status       TEXT DEFAULT 'open',  -- open(filling) | ready | claimed | done
  claimed_by   TEXT,
  claimed_ts   INTEGER,
  done_ts      INTEGER,
  scanned      INTEGER DEFAULT 0,
  flagged      INTEGER DEFAULT 0,
  confirmed    INTEGER DEFAULT 0,
  errors       INTEGER DEFAULT 0,
  created_ts   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_batches_status ON batches(status);

-- 3) Findings — per flagged/confirmed domain WITH verbatim proof (only per-domain result writes)
CREATE TABLE IF NOT EXISTS findings (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  domain          TEXT NOT NULL,
  business        TEXT,
  phone           TEXT,
  category        TEXT,             -- gambling|pharma|adult|deface|cloak|foreign|malware|redirect
  layers          TEXT,             -- which detection layers fired: L1KW,L2CLOAK,...
  proof_snippet   TEXT,             -- verbatim injected text
  proof_url       TEXT,             -- exact URL where found
  http_status     INTEGER,
  stage1_score    INTEGER,
  stage2_verdict  TEXT,             -- confirmed|benign|uncertain (Gemini)
  stage2_reason   TEXT,
  stage2_category TEXT,
  confirmed       INTEGER DEFAULT 0, -- 1 = Stage-2 confirmed hacked
  pass_no         INTEGER DEFAULT 1,
  first_ts        INTEGER,
  ts              INTEGER
);
CREATE INDEX IF NOT EXISTS idx_findings_domain    ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_confirmed ON findings(confirmed);
CREATE INDEX IF NOT EXISTS idx_findings_category  ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_ts        ON findings(ts);

-- 4) Daily aggregate stats (Asia/Dhaka day) — category breakdown for the dashboard
CREATE TABLE IF NOT EXISTS daily_stats (
  day       TEXT PRIMARY KEY,        -- YYYY-MM-DD
  harvested INTEGER DEFAULT 0,
  scanned   INTEGER DEFAULT 0,
  flagged   INTEGER DEFAULT 0,
  confirmed INTEGER DEFAULT 0,
  errors    INTEGER DEFAULT 0,
  gambling  INTEGER DEFAULT 0,
  pharma    INTEGER DEFAULT 0,
  adult     INTEGER DEFAULT 0,
  deface    INTEGER DEFAULT 0,
  cloak     INTEGER DEFAULT 0,
  foreign_lang INTEGER DEFAULT 0,
  malware   INTEGER DEFAULT 0,
  redirect  INTEGER DEFAULT 0
);

-- 5) Hourly aggregate stats (finer chart + live rate)
CREATE TABLE IF NOT EXISTS hourly_stats (
  hour      TEXT PRIMARY KEY,        -- YYYY-MM-DD-HH
  scanned   INTEGER DEFAULT 0,
  flagged   INTEGER DEFAULT 0,
  confirmed INTEGER DEFAULT 0,
  errors    INTEGER DEFAULT 0
);

-- 6) Global counters (single-row metrics for the dashboard headline)
CREATE TABLE IF NOT EXISTS counters (
  metric TEXT PRIMARY KEY,
  value  INTEGER DEFAULT 0
);

-- 7) Per-source harvest log
CREATE TABLE IF NOT EXISTS harvest_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  source      TEXT,
  found       INTEGER,
  new_domains INTEGER,
  dups        INTEGER,
  ts          INTEGER,
  note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_harvest_ts ON harvest_log(ts);

-- 8) Source state / cursors (per-source progress so we don't re-harvest endlessly)
CREATE TABLE IF NOT EXISTS source_state (
  source          TEXT PRIMARY KEY,
  cursor          TEXT,
  last_run        INTEGER,
  total_harvested INTEGER DEFAULT 0,
  enabled         INTEGER DEFAULT 1
);

-- 9) Recent events feed (capped; flagged/confirmed/errors/harvest/worker). Trimmed by /stats cron.
CREATE TABLE IF NOT EXISTS events (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  kind   TEXT,                       -- confirmed|flagged|error|harvest|worker|info
  domain TEXT,
  detail TEXT,
  ts     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

-- 10) Worker/job heartbeats (live worker status on the dashboard)
CREATE TABLE IF NOT EXISTS workers_heartbeat (
  worker_id     TEXT PRIMARY KEY,
  last_seen     INTEGER,
  scanned_total INTEGER DEFAULT 0,
  current_batch INTEGER,
  state         TEXT
);

-- 11) Gemini key usage (Stage-2 verification quota tracking)
CREATE TABLE IF NOT EXISTS key_usage (
  key_id       TEXT PRIMARY KEY,
  day          TEXT,
  requests     INTEGER DEFAULT 0,
  successes    INTEGER DEFAULT 0,
  rate_limited INTEGER DEFAULT 0,
  last_used    INTEGER
);
