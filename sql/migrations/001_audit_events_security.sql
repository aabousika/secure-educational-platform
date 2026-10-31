-- Additive upgrade for databases created before security monitoring (also applied automatically at startup).
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS outcome VARCHAR(16) NOT NULL DEFAULT 'success';
CREATE INDEX IF NOT EXISTS ix_audit_events_created_at ON audit_events (created_at);
