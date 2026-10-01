"""Seed a fresh store with fictional local test users."""

from .service import AuthService

# Fictional accounts only; passwords are for the local test environment.
FICTIONAL_USERS = {
    "ada.lovelace": "Fiction!Ada-2026",
    "alan.turing": "Fiction!Alan-2026",
    "grace.hopper": "Fiction!Grace-2026",
}


def seed(auth, users=FICTIONAL_USERS):
    for username, password in users.items():
        try:
            auth.create_user(username, password)
        except ValueError:
            pass
    return list(users)


def build_service(store_path, **kwargs):
    auth = AuthService(store_path, **kwargs)
    seed(auth)
    return auth
