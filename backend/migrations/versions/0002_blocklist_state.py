"""Ensure the advisory blocklist schema and threshold defaults exist.

Revision ID: 0002_blocklist
Revises: 0001_bootstrap
"""
from alembic import op

revision = "0002_blocklist"
down_revision = "0001_bootstrap"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE flows ADD COLUMN IF NOT EXISTS "
        "blocked BOOLEAN NOT NULL DEFAULT FALSE"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_blocked_ips_active "
        "ON blocked_ips (active)"
    )

    op.execute("""
        INSERT INTO thresholds (key, value, description) VALUES
            ('entropy_high', 7.2, 'Payload Shannon entropy threshold (bits)'),
            ('dns_label_entropy', 3.8, 'DNS subdomain label entropy threshold'),
            ('dns_label_len', 60, 'DNS subdomain label length threshold (chars)'),
            ('dns_qps', 15, 'DNS queries-per-second threshold'),
            ('iat_cv_low', 0.05, 'IAT coefficient of variation - regularity threshold'),
            ('iat_autocorr', 0.80, 'IAT lag-1 autocorrelation threshold'),
            ('http_ua_entropy', 4.5, 'HTTP User-Agent entropy threshold'),
            ('http_url_entropy', 4.8, 'HTTP URL entropy threshold'),
            ('icmp_payload_len', 64, 'ICMP payload length threshold (bytes)'),
            ('icmp_payload_entropy', 6.0, 'ICMP payload entropy threshold'),
            ('alert_score', 0.40, 'Minimum final_score to raise an alert'),
            ('ml_contamination', 0.05, 'Isolation Forest assumed contamination rate')
        ON CONFLICT (key) DO NOTHING
    """)


def downgrade() -> None:
    raise RuntimeError("The blocklist migration is intentionally irreversible to preserve analyst state.")
