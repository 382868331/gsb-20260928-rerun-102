import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from auth_core.seed import build_service
from auth_core.service import AuthService


@pytest.fixture
def store_path(tmp_path):
    return str(tmp_path / "auth-state.json")


@pytest.fixture
def auth(store_path):
    return build_service(store_path, access_ttl=3600, refresh_ttl=86400)


@pytest.fixture
def short_auth(store_path):
    from auth_core.seed import seed

    service = AuthService(store_path, access_ttl=1, refresh_ttl=1)
    seed(service)
    return service
