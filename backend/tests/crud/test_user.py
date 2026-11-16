from datetime import timedelta
from unittest.mock import patch

from fastapi.encoders import jsonable_encoder
from pwdlib.hashers.bcrypt import BcryptHasher
from sqlmodel import Session

from app import crud
from app.core.security import verify_password
from app.models import User, UserCreate, UserUpdate, get_datetime_utc
from tests.utils.utils import random_email, random_lower_string


def test_create_user(db: Session) -> None:
    email = random_email()
    password = random_lower_string()
    user_in = UserCreate(email=email, password=password)
    user = crud.create_user(session=db, user_create=user_in)
    assert user.email == email
    assert hasattr(user, "hashed_password")


def test_authenticate_user(db: Session) -> None:
    email = random_email()
    password = random_lower_string()
    user_in = UserCreate(email=email, password=password)
    user = crud.create_user(session=db, user_create=user_in)
    authenticated_user = crud.authenticate(session=db, email=email, password=password)
    assert authenticated_user
    assert user.email == authenticated_user.email


def test_not_authenticate_user(db: Session) -> None:
    email = random_email()
    password = random_lower_string()
    user = crud.authenticate(session=db, email=email, password=password)
    assert user is None


def test_check_if_user_is_active(db: Session) -> None:
    email = random_email()
    password = random_lower_string()
    user_in = UserCreate(email=email, password=password)
    user = crud.create_user(session=db, user_create=user_in)
    assert user.is_active is True


def test_check_if_user_is_active_inactive(db: Session) -> None:
    email = random_email()
    password = random_lower_string()
    user_in = UserCreate(email=email, password=password, is_active=False)
    user = crud.create_user(session=db, user_create=user_in)
    assert user.is_active is False


def test_check_if_user_is_superuser(db: Session) -> None:
    email = random_email()
    password = random_lower_string()
    user_in = UserCreate(email=email, password=password, is_superuser=True)
    user = crud.create_user(session=db, user_create=user_in)
    assert user.is_superuser is True


def test_check_if_user_is_superuser_normal_user(db: Session) -> None:
    username = random_email()
    password = random_lower_string()
    user_in = UserCreate(email=username, password=password)
    user = crud.create_user(session=db, user_create=user_in)
    assert user.is_superuser is False


def test_get_user(db: Session) -> None:
    password = random_lower_string()
    username = random_email()
    user_in = UserCreate(email=username, password=password, is_superuser=True)
    user = crud.create_user(session=db, user_create=user_in)
    user_2 = db.get(User, user.id)
    assert user_2
    assert user.email == user_2.email
    assert jsonable_encoder(user) == jsonable_encoder(user_2)


def test_update_user(db: Session) -> None:
    password = random_lower_string()
    email = random_email()
    user_in = UserCreate(email=email, password=password, is_superuser=True)
    user = crud.create_user(session=db, user_create=user_in)
    new_password = random_lower_string()
    user_in_update = UserUpdate(password=new_password, is_superuser=True)
    if user.id is not None:
        crud.update_user(session=db, db_user=user, user_in=user_in_update)
    user_2 = db.get(User, user.id)
    assert user_2
    assert user.email == user_2.email
    verified, _ = verify_password(new_password, user_2.hashed_password)
    assert verified


def test_authenticate_user_with_bcrypt_upgrades_to_argon2(db: Session) -> None:
    """Test that a user with bcrypt password hash gets upgraded to argon2 on login."""
    email = random_email()
    password = random_lower_string()

    # Create a bcrypt hash directly (simulating legacy password)
    bcrypt_hasher = BcryptHasher()
    bcrypt_hash = bcrypt_hasher.hash(password)
    assert bcrypt_hash.startswith("$2")  # bcrypt hashes start with $2

    # Create user with bcrypt hash directly in the database
    user = User(email=email, hashed_password=bcrypt_hash)
    db.add(user)
    db.commit()
    db.refresh(user)

    # Verify the hash is bcrypt before authentication
    assert user.hashed_password.startswith("$2")

    # Authenticate - this should upgrade the hash to argon2
    authenticated_user = crud.authenticate(session=db, email=email, password=password)
    assert authenticated_user
    assert authenticated_user.email == email

    db.refresh(authenticated_user)

    # Verify the hash was upgraded to argon2
    assert authenticated_user.hashed_password.startswith("$argon2")

    verified, updated_hash = verify_password(
        password, authenticated_user.hashed_password
    )
    assert verified
    # Should not need another update since it's already argon2
    assert updated_hash is None


def _new_user(db: Session) -> tuple[str, str]:
    email = random_email()
    password = random_lower_string()
    crud.create_user(session=db, user_create=UserCreate(email=email, password=password))
    return email, password


def _get(db: Session, email: str) -> User:
    user = crud.get_user_by_email(session=db, email=email)
    assert user
    db.refresh(user)
    return user


def test_failed_login_increments_counter(db: Session) -> None:
    email, _ = _new_user(db)
    assert crud.authenticate(session=db, email=email, password="wrong-password") is None
    user = _get(db, email)
    assert user.failed_login_attempts == 1
    assert user.locked_until is None


def test_account_locks_after_max_failed_attempts(db: Session) -> None:
    email, password = _new_user(db)
    with patch("app.core.config.settings.LOGIN_MAX_FAILED_ATTEMPTS", 3):
        for _ in range(3):
            assert crud.authenticate(session=db, email=email, password="bad") is None
        user = _get(db, email)
        assert user.locked_until is not None
        assert user.failed_login_attempts == 0
        # Correct password is rejected while locked
        assert crud.authenticate(session=db, email=email, password=password) is None


def test_locked_account_does_not_extend_lock(db: Session) -> None:
    email, _ = _new_user(db)
    with patch("app.core.config.settings.LOGIN_MAX_FAILED_ATTEMPTS", 1):
        crud.authenticate(session=db, email=email, password="bad")
        first_lock = _get(db, email).locked_until
        crud.authenticate(session=db, email=email, password="bad")
        assert _get(db, email).locked_until == first_lock


def test_successful_login_resets_failed_attempts(db: Session) -> None:
    email, password = _new_user(db)
    with patch("app.core.config.settings.LOGIN_MAX_FAILED_ATTEMPTS", 3):
        for _ in range(2):
            crud.authenticate(session=db, email=email, password="bad")
        assert crud.authenticate(session=db, email=email, password=password)
        assert _get(db, email).failed_login_attempts == 0


def test_expired_lock_allows_login(db: Session) -> None:
    email, password = _new_user(db)
    user = _get(db, email)
    user.locked_until = get_datetime_utc() - timedelta(minutes=1)
    db.add(user)
    db.commit()
    authenticated = crud.authenticate(session=db, email=email, password=password)
    assert authenticated
    assert authenticated.locked_until is None


def test_authenticate_unknown_email_uses_dummy_hash(db: Session) -> None:
    with patch("app.crud.verify_password", return_value=(False, None)) as mocked:
        assert (
            crud.authenticate(session=db, email=random_email(), password="whatever")
            is None
        )
    mocked.assert_called_once_with("whatever", crud.DUMMY_HASH)


def test_locked_account_still_verifies_password(db: Session) -> None:
    email, password = _new_user(db)
    user = _get(db, email)
    user.locked_until = get_datetime_utc() + timedelta(minutes=5)
    db.add(user)
    db.commit()
    with patch("app.crud.verify_password", return_value=(True, None)) as mocked:
        assert crud.authenticate(session=db, email=email, password=password) is None
    mocked.assert_called_once()
