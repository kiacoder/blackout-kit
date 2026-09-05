"""
Blackout Kit - Role-Based Access Control (RBAC) & Team Accounts (Phase 7).
Uses SQLAlchemy for ORM database persistence of organizations and users,
and python-jose / PyJWT for JWT authentication tokens.
Roles: Owner (full access), Admin (manage team/policies), Member (read-only/limited).
"""
import datetime
from datetime import timezone
import logging
from typing import Any, Dict, List, Optional
from jose import JWTError, jwt
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

from blackoutkit import APP_DATA_DIR

_log = logging.getLogger(__name__)

DB_PATH = APP_DATA_DIR / "rbac.db"
SECRET_KEY = "blackout-kit-enterprise-rbac-secret-key-change-me"
ALGORITHM = "HS256"


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now_utc)

    users: Mapped[List["User"]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(32), default="Member")  # Owner, Admin, Member
    org_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.org_id"))
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now_utc)

    organization: Mapped[Organization] = relationship(back_populates="users")


class RBACManager:
    """Manages Orgs, Users, Roles, and JWT Auth tokens."""

    def __init__(self, db_url: Optional[str] = None):
        if db_url is None:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            db_url = f"sqlite:///{DB_PATH}"
        self.engine = create_engine(db_url, echo=False)
        Base.metadata.create_all(self.engine)

    def create_organization(self, org_id: str, name: str) -> Dict[str, Any]:
        with Session(self.engine) as session:
            existing = session.scalar(select(Organization).where(Organization.org_id == org_id))
            if existing:
                return {"org_id": existing.org_id, "name": existing.name}
            org = Organization(org_id=org_id, name=name)
            session.add(org)
            session.commit()
            return {"org_id": org.org_id, "name": org.name}

    def create_user(self, user_id: str, email: str, org_id: str, role: str = "Member") -> Dict[str, Any]:
        if role not in {"Owner", "Admin", "Member"}:
            role = "Member"
        with Session(self.engine) as session:
            existing = session.scalar(select(User).where(User.user_id == user_id))
            if existing:
                existing.email = email
                existing.org_id = org_id
                existing.role = role
                session.commit()
                return {"user_id": existing.user_id, "email": existing.email, "org_id": existing.org_id, "role": existing.role}

            user = User(user_id=user_id, email=email, org_id=org_id, role=role)
            session.add(user)
            session.commit()
            return {"user_id": user.user_id, "email": user.email, "org_id": user.org_id, "role": user.role}

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        with Session(self.engine) as session:
            u = session.scalar(select(User).where(User.user_id == user_id))
            if u:
                return {"user_id": u.user_id, "email": u.email, "org_id": u.org_id, "role": u.role}
            return None

    def issue_jwt_token(self, user_id: str, expires_delta_hours: int = 24) -> str:
        u = self.get_user(user_id)
        if not u:
            raise ValueError("User not found")
        expire = datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=expires_delta_hours)
        payload = {"sub": u["user_id"], "email": u["email"], "org_id": u["org_id"], "role": u["role"], "exp": expire}
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError:
            return None

    def check_permission(self, role: str, action: str) -> bool:
        """
        Permission matrix:
          Owner: Full permissions (*).
          Admin: Manage team users, policy updates, trigger remote actions.
          Member: Read-only metrics, view alerts.
        """
        role = role.capitalize()
        if role == "Owner":
            return True
        elif role == "Admin":
            return action in {"manage_users", "update_policies", "trigger_actions", "view_reports"}
        elif role == "Member":
            return action in {"view_reports", "view_metrics"}
        return False


_rbac = RBACManager()


def create_org(org_id: str, name: str) -> Dict[str, Any]:
    return _rbac.create_organization(org_id, name)


def create_team_member(user_id: str, email: str, org_id: str, role: str = "Member") -> Dict[str, Any]:
    return _rbac.create_user(user_id, email, org_id, role)


def authenticate_token(token: str) -> Optional[Dict[str, Any]]:
    return _rbac.verify_jwt_token(token)


def check_role_permission(role: str, action: str) -> bool:
    return _rbac.check_permission(role, action)
