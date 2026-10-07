from __future__ import annotations

import os

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer,
    String, Text, false, func, true,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession, async_sessionmaker, create_async_engine,
)
from sqlalchemy.orm import declarative_base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://covertscope:covertscope@localhost:5432/covertscope",
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

Base = declarative_base()


class Flow(Base):
    __tablename__ = "flows"

    id = Column(BigInteger, primary_key=True)
    flow_uid = Column(BigInteger, nullable=False)
    src_ip = Column(String(64), nullable=False)
    src_port = Column(Integer)
    dst_ip = Column(String(64), nullable=False)
    dst_port = Column(Integer)
    l4_proto = Column(String(8))
    ndpi_protocol = Column(String(64))
    ndpi_proto_id = Column(Integer)
    packets = Column(Integer, default=0)
    bytes = Column(BigInteger, default=0)
    duration_ms = Column(Integer, default=0)

    iat_mean = Column(Float)
    iat_variance = Column(Float)
    iat_cv = Column(Float)
    iat_autocorr1 = Column(Float)

    payload_entropy = Column(Float)
    avg_pkt_len = Column(Float)

    dns_query = Column(Text)
    dns_entropy = Column(Float)
    dns_qlen = Column(Integer)
    dns_qps = Column(Float)

    http_host = Column(String(255))
    http_user_agent = Column(Text)
    http_url = Column(Text)
    http_ua_entropy = Column(Float)

    icmp_payload_len = Column(Integer)
    icmp_payload_entropy = Column(Float)

    covert_flags = Column(Integer, default=0)
    anomaly_score = Column(Float, default=0)
    is_covert = Column(Boolean, default=False)
    blocked = Column(
        Boolean, default=False, server_default=false(), nullable=False
    )  # src or dst matched an active BlockedIP entry

    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True)
    flow_id = Column(BigInteger, ForeignKey("flows.id", ondelete="CASCADE"))
    covert_type = Column(String(32), nullable=False)
    stat_score = Column(Float, default=0)
    ml_score = Column(Float, default=0)
    final_score = Column(Float, nullable=False)
    confidence = Column(String(16), nullable=False)
    reason = Column(Text)
    recommendation = Column(Text)
    acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Threshold(Base):
    __tablename__ = "thresholds"

    key = Column(String(64), primary_key=True)
    value = Column(Float, nullable=False)
    description = Column(Text)
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class BlockedIP(Base):
    """A soft/advisory block an analyst raised from an alert or flow.

    CovertScope is a passive monitor — it classifies traffic, it doesn't sit
    inline on the network path, so this table does not itself stop any
    packets. What it does:
      1. Marks any future matching flow (src or dst) so a re-offending
         source is immediately visible instead of blending back into the
         flow list.
      2. Is exposed via GET /api/blocklist as a simple feed an actual
         enforcement point (host firewall, edge router/ACL, WAF) can poll
         and apply. See SECURITY.md for why we didn't have the backend
         shell out to iptables/nftables directly.
    """
    __tablename__ = "blocked_ips"

    id = Column(BigInteger, primary_key=True)
    ip = Column(String(64), nullable=False, unique=True)
    reason = Column(Text)
    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    active = Column(Boolean, default=True, server_default=true(), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


Index("idx_blocked_ips_active", BlockedIP.active)


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
