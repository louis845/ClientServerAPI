import uuid

from .login_session import LoginSession

class SessionHandler():
    """
    All functions should be called in the main server thread/process. For ThreadedAPIServer, the
    functions can be called in other threads with the lock acquired. For ProcessedAPIServer, only
    call these functions in the main process.
    """

    session_dict: dict[str, LoginSession]

    def __init__(self):
        self.session_dict = {}
    
    def clear_all_logins(self):
        """
        Clear all login sessions. This means forcing all users to log out.
        """
        for key in self.session_dict:
            self.session_dict[key].invalidate()
    
    def create_session(self, uuid: str, session: LoginSession) -> None:
        """
        Create a new session for a user.
        """
        if uuid in self.session_dict:
            raise ValueError("Session already exists for this UUID.")
        self.session_dict[uuid] = session
    
    def get_session(self, session_token: str) -> LoginSession:
        """
        Get the session for a user.
        """
        return self.session_dict.get(session_token)
    
    def generateSessionToken(self) -> str:
        """Generate a new session token, and make sure it is unique."""
        token = str(uuid.uuid4())
        while token in self.session_dict:
            token = str(uuid.uuid4())
        return token
    
    def clean_sessions(self) -> tuple[int, int, list[LoginSession]]:
        """
        Clean up any invalid sessions.
        """
        num_cleaned = 0
        removed_sessions = []
        for key in list(self.session_dict.keys()):
            if not self.session_dict[key]._is_valid.value:
                removed_sessions.append(self.session_dict.pop(key))
                num_cleaned += 1
        num_remaining = len(self.session_dict)
        return num_cleaned, num_remaining, removed_sessions