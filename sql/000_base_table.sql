-- Base table for rsyslog firewalld log ingestion
-- This table is populated by rsyslog via /etc/rsyslog.d/firewalld_log.conf
-- Review before applying to production.

-- Database: intrusion
-- Schema: eng_ops

CREATE SCHEMA IF NOT EXISTS eng_ops
    AUTHORIZATION postgres;
COMMENT ON SCHEMA eng_ops
    IS 'schema for engineering operations';

DROP TABLE IF EXISTS eng_ops.firewall_logs CASCADE;

CREATE TABLE IF NOT EXISTS eng_ops.firewall_logs (
    id SERIAL PRIMARY KEY,
    log_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    facility text,
    from_host text,
    priority text,
    devicereportedtime timestamp without time zone DEFAULT NULL,
    recievedat timestamp without time zone DEFAULT NULL,
    infounitid text,
    syslogtag text,
    action text COLLATE pg_catalog."default",
    interface text COLLATE pg_catalog."default",
    mac_address text,
    src_ip inet,
    dst_ip inet,
    len integer,
    tos text,
    prec text,
    ttl integer,
    ip_id integer,
    df text,
    protocol text COLLATE pg_catalog."default",
    spt integer,
    dport integer,
    window_size integer,
    res text,
    syn text,
    urgp integer,
    ack text,
    psh text,
    message text COLLATE pg_catalog."default"
)
TABLESPACE pg_default;

-- Grant permissions (adjust username as needed)
-- ALTER TABLE eng_ops.firewall_logs OWNER TO intrusion_logger;
-- GRANT ALL ON SCHEMA eng_ops TO intrusion_logger;
-- GRANT ALL ON TABLE eng_ops.firewall_logs TO intrusion_logger;
