import os
from datetime import datetime

from app.db.base import Base
from app.models.proxy import ProxyTypes
from app.models.user import UserStatus
from sqlalchemy import (JSON, BigInteger, Column, DateTime, Enum, ForeignKey,
                        Integer, String, Table)
from sqlalchemy.orm import relationship

from app.xray import INBOUNDS


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    users = relationship("User", back_populates="admin")
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    proxies = relationship("Proxy", back_populates="user", cascade="all, delete-orphan")
    status = Column(Enum(UserStatus), default=UserStatus.active)
    used_traffic = Column(BigInteger, default=0)
    data_limit = Column(BigInteger, nullable=True)
    expire = Column(Integer, nullable=True)
    admin_id = Column(Integer, ForeignKey("admins.id"))
    admin = relationship("Admin", back_populates="users")
    created_at = Column(DateTime, default=datetime.utcnow)

    @property
    def excluded_inbounds(self):
        data = {}
        for p in self.proxies:
            data[p.type] = [i.tag for i in p.excluded_inbounds]
        return data

    @property
    def inbounds(self):
        inbounds = {}
        for proxy_type, excluded_tags in self.excluded_inbounds.items():
            for inbound in INBOUNDS.get(proxy_type, []):
                if inbound['tag'] in excluded_tags:
                    continue
                try:
                    inbounds[proxy_type].append(inbound['tag'])
                except KeyError:
                    inbounds[proxy_type] = [inbound['tag']]

        return inbounds


excluded_inbounds_association = Table(
    "exclude_inbounds_association",
    Base.metadata,
    Column("proxy_id", ForeignKey("proxies.id")),
    Column("inbound_tag", ForeignKey("inbounds.tag")),
)


class Proxy(Base):
    __tablename__ = "proxies"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="proxies")
    type = Column(Enum(ProxyTypes), nullable=False)
    settings = Column(JSON, nullable=False)
    excluded_inbounds = relationship("ProxyInbound", secondary=excluded_inbounds_association)


class ProxyInbound(Base):
    __tablename__ = "inbounds"

    id = Column(Integer, primary_key=True)
    tag = Column(String, unique=True, nullable=False, index=True)


class System(Base):
    __tablename__ = "system"

    id = Column(Integer, primary_key=True, index=True)
    uplink = Column(BigInteger, default=0)
    downlink = Column(BigInteger, default=0)


class JWT(Base):
    __tablename__ = "jwt"

    id = Column(Integer, primary_key=True)
    secret_key = Column(String(64), nullable=False, default=lambda: os.urandom(32).hex())
