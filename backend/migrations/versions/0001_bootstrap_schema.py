"""Create the initial CovertScope schema without replacing existing tables.

Revision ID: 0001_bootstrap
Revises:
"""
from alembic import op

revision = "0001_bootstrap"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Keep this DDL fixed: later model changes belong in new revisions.
    # IF NOT EXISTS lets databases created from schema.sql adopt Alembic
    # without dropping or rewriting their existing data.
    statements = (
        """
        CREATE TABLE IF NOT EXISTS flows (
            id BIGSERIAL PRIMARY KEY,
            flow_uid BIGINT NOT NULL,
            src_ip INET NOT NULL,
            src_port INTEGER,
            dst_ip INET NOT NULL,
            dst_port INTEGER,
            l4_proto VARCHAR(8),
            ndpi_protocol VARCHAR(64),
            ndpi_proto_id INTEGER,
            packets INTEGER DEFAULT 0,
            bytes BIGINT DEFAULT 0,
            duration_ms INTEGER DEFAULT 0,
            iat_mean DOUBLE PRECISION,
            iat_variance DOUBLE PRECISION,
            iat_cv DOUBLE PRECISION,
            iat_autocorr1 DOUBLE PRECISION,
            payload_entropy DOUBLE PRECISION,
            avg_pkt_len DOUBLE PRECISION,
            dns_query TEXT,
            dns_entropy DOUBLE PRECISION,
            dns_qlen INTEGER,
            dns_qps DOUBLE PRECISION,
            http_host VARCHAR(255),
            http_user_agent TEXT,
            http_url TEXT,
            http_ua_entropy DOUBLE PRECISION,
            icmp_payload_len INTEGER,
            icmp_payload_entropy DOUBLE PRECISION,
            covert_flags INTEGER DEFAULT 0,
            anomaly_score DOUBLE PRECISION DEFAULT 0,
            is_covert BOOLEAN DEFAULT FALSE,
            blocked BOOLEAN NOT NULL DEFAULT FALSE,
            first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id BIGSERIAL PRIMARY KEY,
            flow_id BIGINT REFERENCES flows(id) ON DELETE CASCADE,
            covert_type VARCHAR(32) NOT NULL,
            stat_score DOUBLE PRECISION DEFAULT 0,
            ml_score DOUBLE PRECISION DEFAULT 0,
            final_score DOUBLE PRECISION NOT NULL,
            confidence VARCHAR(16) NOT NULL,
            reason TEXT,
            recommendation TEXT,
            acknowledged BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id BIGSERIAL PRIMARY KEY,
            ip VARCHAR(64) NOT NULL UNIQUE,
            reason TEXT,
            alert_id BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS thresholds (
            key VARCHAR(64) PRIMARY KEY,
            value DOUBLE PRECISION NOT NULL,
            description TEXT,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_flows_created_at ON flows (created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_flows_ndpi_protocol ON flows (ndpi_protocol)",
        "CREATE INDEX IF NOT EXISTS idx_flows_is_covert ON flows (is_covert)",
        "CREATE INDEX IF NOT EXISTS idx_flows_anomaly_score ON flows (anomaly_score DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_confidence ON alerts (confidence)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_covert_type ON alerts (covert_type)",
        "CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips (active)",
    )
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    raise RuntimeError(
        "The bootstrap migration is intentionally irreversible to preserve existing database data."
    )
