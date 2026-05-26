from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Column, String, Text, DateTime, Integer, Float, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship

from src.api.database import Base


def _uuid():
    return uuid.uuid4().hex[:12]


class User(Base):
    __tablename__ = "users"

    id = Column(String(12), primary_key=True, default=_uuid)
    username = Column(String(64), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.now)

    scans = relationship("Scan", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(12), primary_key=True, default=_uuid)
    user_id = Column(String(12), ForeignKey("users.id"), nullable=True)
    scan_type = Column(String(32), nullable=False)
    target = Column(String(512), nullable=False)
    status = Column(String(16), default="pending")
    started_at = Column(DateTime, default=datetime.now)
    finished_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    total_findings = Column(Integer, default=0)
    severity_summary = Column(JSON, default=dict)
    error = Column(Text, nullable=True)
    remediation_plan = Column(JSON, nullable=True)
    finding_status_counts = Column(JSON, default=dict)

    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(12), primary_key=True, default=_uuid)
    scan_id = Column(String(12), ForeignKey("scans.id"), nullable=False)
    name = Column(String(256), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(16), default="info")
    url = Column(String(512), default="")
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, default="")
    references = Column(JSON, default=list)
    source = Column(String(32), nullable=True)
    status = Column(String(16), default="open")
    resolved_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="findings")
