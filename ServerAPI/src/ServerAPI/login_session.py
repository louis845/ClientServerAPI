from typing import Union, Any, Optional
import multiprocessing as mp
import time
import hashlib

class LoginSession:
    _is_valid: Any # boolean value to check if the session is valid. This is a multiprocessing.Value object to allow to be passed to subprocesses to invalidate the session.
    _username: str
    _session_token: str
    _creation_time: float
    _last_accessed: Any # float value to store the last time the session was accessed. This is a multiprocessing.Value object to allow to be passed to subprocesses to update the last accessed time.

    # cache stuff
    _hash_cache: Optional[str]

    def __init__(self, username: str, session_token: str):
        self._username = username
        self._session_token = session_token
        self._creation_time = time.time()
        self._is_valid = mp.Value("b", True)
        self._last_accessed = mp.Value("d", time.time())

        self._hash_cache = None

    def get_username(self) -> str:
        """Get the username associated with this session."""
        return self._username

    def invalidate(self) -> None:
        """Invalidate the session."""
        self._is_valid.value = False
    
    def get_hashed_session_token(self) -> str:
        """Get the hashed session token as SHA-256 string"""
        if self._hash_cache is None:
            self._hash_cache = hashlib.sha256(self._session_token.encode()).hexdigest()
        return self._hash_cache

    def get_last_accessed(self) -> float:
        return float(self._last_accessed.value)