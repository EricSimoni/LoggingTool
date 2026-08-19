-- Keep raw rsyslog ingestion separate from application enrichment.
-- Review before applying to production.

CREATE TABLE IF NOT EXISTS eng_ops.firewall_event_enrichment (
    firewall_log_id INTEGER PRIMARY KEY
        REFERENCES eng_ops.firewall_logs(id)
        ON DELETE CASCADE,

    processed_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    country TEXT,
    region TEXT,
    city TEXT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    postal TEXT,
    timezone TEXT,

    severity TEXT,
    classification TEXT
);

CREATE INDEX IF NOT EXISTS idx_firewall_enrichment_country
    ON eng_ops.firewall_event_enrichment(country);
