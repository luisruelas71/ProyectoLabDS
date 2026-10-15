from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from typing import Dict


@dataclass(frozen=True)
class Session:
    role: str
    username: str
    access_granted: bool


class TeacherAuthService:
    def __init__(self, users: Dict[str, str]) -> None:
        self._users = users

    @staticmethod
    def hash_password(password: str, salt: str | None = None) -> str:
        normalized_salt = salt or os.urandom(16).hex()
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(normalized_salt),
            200_000,
        ).hex()
        return f"{normalized_salt}${digest}"

    @staticmethod
    def verify_password(password: str, stored_password: str) -> bool:
        salt, _, stored_digest = stored_password.partition("$")
        if not salt or not stored_digest:
            return False

        generated = TeacherAuthService.hash_password(password, salt=salt)
        _, _, generated_digest = generated.partition("$")
        return hmac.compare_digest(stored_digest, generated_digest)

    def login(self, username: str, password: str) -> Session | None:
        stored_hash = self._users.get(username)
        if not stored_hash:
            return None

        if not self.verify_password(password, stored_hash):
            return None

        return Session(role="teacher", username=username, access_granted=True)
