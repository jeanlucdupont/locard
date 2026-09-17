PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS evidence_files (
 sha256 TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, first_seen_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_locations (
 file_sha256 TEXT NOT NULL REFERENCES evidence_files(sha256), source_file TEXT NOT NULL,
 PRIMARY KEY(file_sha256, source_file)
);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, file_sha256 TEXT NOT NULL REFERENCES evidence_files(sha256),
 source_file TEXT NOT NULL, record_offset INTEGER NOT NULL, record_id INTEGER,
 timestamp_utc TEXT, timestamp_original TEXT, timestamp_status TEXT NOT NULL,
 hostname TEXT, computer TEXT, channel TEXT, provider TEXT, event_id INTEGER, level INTEGER,
 user_sid TEXT, username TEXT, artifact_type TEXT,
 process_name TEXT, process_id INTEGER, parent_process_name TEXT, parent_process_id INTEGER,
 command_line TEXT, source_ip TEXT, source_port INTEGER, destination_ip TEXT, destination_port INTEGER,
 logon_type INTEGER, logon_id TEXT, service_name TEXT, task_name TEXT, script_block TEXT,
 event_data_json TEXT NOT NULL, normalization_warnings_json TEXT NOT NULL,
 normalizer_version TEXT NOT NULL, raw_xml TEXT NOT NULL,
 UNIQUE(file_sha256, record_offset)
);
CREATE TABLE IF NOT EXISTS ingestion_runs (
 id INTEGER PRIMARY KEY, source_file TEXT NOT NULL,
 file_sha256 TEXT REFERENCES evidence_files(sha256), started_utc TEXT NOT NULL,
 finished_utc TEXT, status TEXT NOT NULL, inserted_count INTEGER NOT NULL DEFAULT 0,
 duplicate_count INTEGER NOT NULL DEFAULT 0, error_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ingestion_errors (
 id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES ingestion_runs(id),
 record_offset INTEGER, record_id INTEGER, stage TEXT NOT NULL, message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_time ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_event ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_host ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_user ON events(username COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_process ON events(process_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_dest_ip ON events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_artifact ON events(artifact_type);
PRAGMA user_version = 1;
