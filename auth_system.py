from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
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
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def login(self, username: str, password: str) -> Session | None:
        stored_hash = self._users.get(username)
        if not stored_hash:
            return None

        provided_hash = self.hash_password(password)
        if not hmac.compare_digest(stored_hash, provided_hash):
            return None

        return Session(role="teacher", username=username, access_granted=True)
