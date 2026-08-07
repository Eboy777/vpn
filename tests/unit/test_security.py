from __future__ import annotations

import re
import uuid
from collections.abc import Callable

import pytest
from cryptography.exceptions import InvalidTag

from vpn_service.config import Settings
from vpn_service.security.credentials import ProxyCredentialsCipher
from vpn_service.security.tokens import TokenHasher


def test_tokens_are_fixed_length_domain_separated_and_not_stored_raw(
    settings_factory: Callable[..., Settings],
) -> None:
    hasher = TokenHasher(settings_factory())

    session = hasher.issue("pairing_session")
    start = hasher.issue("telegram_start")
    device = hasher.issue("device")

    assert all(len(token.raw) == 43 for token in (session, start, device))
    assert len({session.raw, start.raw, device.raw}) == 3
    assert all(len(token.digest) == 32 for token in (session, start, device))
    assert hasher.candidates("pairing_session", session.raw) == [("v1", session.digest)]
    assert hasher.digest("telegram_start", session.key_id, session.raw) != session.digest


def test_proxy_credentials_use_aead_and_user_bound_aad(
    settings_factory: Callable[..., Settings],
) -> None:
    cipher = ProxyCredentialsCipher(settings_factory())
    user_id = uuid.uuid4()
    credentials = cipher.generate(user_id)

    assert re.fullmatch(r"u_[a-z0-9]{26}", credentials.username)
    assert re.fullmatch(r"[A-Za-z0-9_-]{32}", credentials.password)
    assert credentials.password.encode() not in credentials.password_ciphertext
    assert cipher.decrypt(user_id, credentials.password_ciphertext) == credentials.password
    with pytest.raises(InvalidTag):
        cipher.decrypt(uuid.uuid4(), credentials.password_ciphertext)
