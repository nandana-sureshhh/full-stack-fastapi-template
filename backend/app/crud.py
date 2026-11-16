import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, update
from sqlmodel import Session, select

from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.models import Item, ItemCreate, User, UserCreate, UserUpdate, get_datetime_utc


def create_user(*, session: Session, user_create: UserCreate) -> User:
    db_obj = User.model_validate(
        user_create, update={"hashed_password": get_password_hash(user_create.password)}
    )
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}
    if "password" in user_data:
        password = user_data["password"]
        hashed_password = get_password_hash(password)
        extra_data["hashed_password"] = hashed_password
    db_user.sqlmodel_update(user_data, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


def get_user_by_email(*, session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    session_user = session.exec(statement).first()
    return session_user


# Dummy hash to use for timing attack prevention when user is not found
# This is an Argon2 hash of a random password, used to ensure constant-time comparison
DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$MjQyZWE1MzBjYjJlZTI0Yw$YTU4NGM5ZTZmYjE2NzZlZjY0ZWY3ZGRkY2U2OWFjNjk"


def register_failed_login(*, session: Session, user_id: uuid.UUID) -> None:
    """Count one failed login and lock the account when the limit is reached.

    A single atomic UPDATE (no read-modify-write), so concurrent failed logins
    cannot undercount. When the limit is reached the counter restarts at 0, so
    the user gets a fresh set of attempts once the lock has expired.
    """
    new_count = User.failed_login_attempts + 1  # type: ignore[operator]
    reached = new_count >= settings.LOGIN_MAX_FAILED_ATTEMPTS
    lock_until = get_datetime_utc() + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
    session.execute(
        update(User)
        .where(User.id == user_id)  # type: ignore[arg-type]
        .values(
            failed_login_attempts=case((reached, 0), else_=new_count),
            locked_until=case((reached, lock_until), else_=User.locked_until),
        )
    )
    session.commit()


def clear_login_lockout(*, session: Session, user_id: uuid.UUID) -> None:
    """Reset the failure counter and remove any lock."""
    session.execute(
        update(User)
        .where(User.id == user_id)  # type: ignore[arg-type]
        .values(failed_login_attempts=0, locked_until=None)
    )
    session.commit()


def is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=UTC)
    return locked_until > datetime.now(UTC)


def authenticate(*, session: Session, email: str, password: str) -> User | None:
    db_user = get_user_by_email(session=session, email=email)
    if not db_user:
        # Prevent timing attacks by running password verification even when user doesn't exist
        # This ensures the response time is similar whether or not the email exists
        verify_password(password, DUMMY_HASH)
        # Also mirror the database write a failed login performs (matches no row),
        # so unknown emails are not distinguishable by the missing write.
        register_failed_login(session=session, user_id=uuid.uuid4())
        return None
    # Always verify, even for a locked account, so timing does not reveal the lock.
    verified, updated_password_hash = verify_password(password, db_user.hashed_password)
    if is_locked(db_user):
        # Same result as a wrong password, even if this password is correct.
        # Failures are not counted while locked, so the lock cannot be extended.
        register_failed_login(session=session, user_id=uuid.uuid4())  # timing parity
        return None
    if not verified:
        register_failed_login(session=session, user_id=db_user.id)
        return None
    if updated_password_hash:
        db_user.hashed_password = updated_password_hash
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
    if db_user.failed_login_attempts or db_user.locked_until:
        clear_login_lockout(session=session, user_id=db_user.id)
        session.refresh(db_user)
    return db_user


def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
    db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item
