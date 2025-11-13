"""Session store abstraction with optional Redis backend.

Provides a minimal API:
- get_session(session_id) -> list[dict]
- append_turn(session_id, turn_dict)
- new_session() -> session_id

Falls back to in-memory dictionary when Redis is disabled or unavailable.
"""

from __future__ import annotations
import os
import json
import uuid
import logging
from typing import Dict, List, Any, Optional

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover
    redis = None  # type: ignore

logger = logging.getLogger(__name__)


class SessionStore:
    def __init__(self, enabled: bool = False, url: Optional[str] = None):
        self.enabled = enabled and bool(url) and redis is not None
        self.url = url
        self._memory: Dict[str, List[Dict[str, Any]]] = {}
        self._redis = None
        if self.enabled:
            try:
                self._redis = redis.Redis.from_url(url, decode_responses=True)
                # quick ping
                self._redis.ping()
                logger.info(f"SessionStore: Connected to Redis at {url}")
            except Exception as e:  # pragma: no cover
                logger.warning(
                    f"SessionStore: Redis connection failed ({e}); falling back to memory"
                )
                self.enabled = False
                self._redis = None

    def new_session(self) -> str:
        sid = str(uuid.uuid4())
        if not self.enabled:
            self._memory[sid] = []
        else:
            self._redis.set(self._key(sid), json.dumps([]))
        return sid

    def get_session(self, session_id: str) -> List[Dict[str, Any]]:
        if not self.enabled:
            return self._memory.get(session_id, [])
        raw = self._redis.get(self._key(session_id))
        if raw is None:
            return []
        try:
            return json.loads(raw)
        except Exception:
            return []

    def append_turn(self, session_id: str, turn: Dict[str, Any]) -> None:
        if not self.enabled:
            self._memory.setdefault(session_id, []).append(turn)
            return
        convo = self.get_session(session_id)
        convo.append(turn)
        self._redis.set(self._key(session_id), json.dumps(convo))

    def _key(self, session_id: str) -> str:
        return f"chat_session:{session_id}"

    def session_length(self, session_id: str) -> int:
        return len(self.get_session(session_id))

    def last_turn(self, session_id: str) -> Optional[Dict[str, Any]]:
        convo = self.get_session(session_id)
        return convo[-1] if convo else None
