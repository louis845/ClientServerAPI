import socket
import ssl
import logging
import os
import abc
from typing import Optional, Callable, Any, Union

from .session_handler import SessionHandler
from .login_session import LoginSession
from . import utils

class AbstractAPIServer(abc.ABC):
    """API Server handling client connections and sessions."""
    host: str
    port: int
    security_params_set: bool
    context: Optional[ssl.SSLContext]

    request_callback: Callable[[str, str, dict[str, Any]], tuple[bool, dict[str, Any]]] # callback function to handle requests
    session_validity_callback: Optional[Callable[[LoginSession], bool]] # callback function to check session validity

    sessions: SessionHandler # active sessions, indexed by session token UUID
    credentials: dict[str, str] # login credentials

    logger: Optional[logging.Logger]
    SERVER_RUNNING: bool

    # other attributes for the connection
    timeout: float
    max_recv_calls_per_request: int
    login_cookie_level: str
    login_cookie_params: dict[str, str] # parameters for the login cookie. derived from login_cookie_level and SSL


    def __init__(self,
                 host: str, port: int,
                 credentials: dict[str, str],
                 request_callback: Callable[[str, str, dict[str, Any]], tuple[bool, dict[str, Any]]],
                 session_validity_callback: Optional[Callable[[LoginSession], bool]]=None,
                 login_cookie_level: str=utils.STRICT,
                 logger: Optional[logging.Logger] = None,
                 timeout: float=5.0,
                 max_recv_calls_per_request: int=1024) -> None:
        """
        Initialize the API server with the given host and port.

        :param host: The host to bind the server to.
        :param port: The port to bind the server to.
        :param credentials: Dictionary of credentials to use for login.
        :param request_callback: Callback function to handle logged in requests, where the input is the username, session token and request body JSON dictionary
            and the output is a boolean representing whether to force_close and response body JSON dictionary. This callback is asynchronous, and should be
            thread or process safe. This means that the callback be a function directly contained in some .py file, so that subprocesses can import it.
            For example, the callback signature could be: `def request_callback(username: str, session_token: str, data: dict[str, Any]) -> [bool, dict[str, Any]]`.
        :param session_validity_callback: Callback function to check the validity of a session, where the input is the login session object, and the output is a
            boolean representing the validity of the session. The server will call this function periodically, and/or when a request with the session token is
            made, to check the validity of the session. This function will be called synchronously in the main server thread/process, so it should be fast.
            For example, the callback signature could be: `def session_validity_callback(login_session: LoginSession) -> bool`.
        :param login_cookie_level: Level of the login cookie. Default is STRICT. See utils.py for more information.
        :param logger: Optional logger to use for logging.
        :param timeout: Timeout for socket operations. Default is 5 seconds.
        :param max_recv_calls_per_request: Maximum number of recv calls to make for a single request. Default is 1024, correpsonding to 4MB (4096 bytes * 1024).
        """

        assert isinstance(host, str), "Host must be a string."
        assert isinstance(port, int), "Port must be an integer."
        assert isinstance(credentials, dict), "Credentials must be a dictionary."
        for key, value in credentials.items():
            assert isinstance(key, str), "All keys in credentials must be strings."
            assert isinstance(value, str), "All values in credentials must be strings."
        if logger is not None:
            assert isinstance(logger, logging.Logger), "Logger must be an instance of logging.Logger or None."
        assert isinstance(timeout, (int, float)), "Timeout must be an integer or float."
        assert isinstance(max_recv_calls_per_request, int), "max_recv_calls_per_request must be an integer."
        assert timeout > 0, "Timeout must be positive."
        assert max_recv_calls_per_request > 0, "max_recv_calls_per_request must be positive."

        assert callable(request_callback), "Request callback must be a callable."
        assert request_callback.__code__.co_argcount == 3, "Request callback must take exactly 3 arguments."

        self.host = host
        self.port = port
        self.security_params_set = False
        self.context = None  # SSL context

        self.request_callback = request_callback # callback function to handle requests
        self.session_validity_callback = session_validity_callback # callback function to check session validity

        self.sessions = SessionHandler()
        self.credentials = credentials

        self.logger = logger
        self.SERVER_RUNNING = False

        self.timeout = timeout
        self.max_recv_calls_per_request = max_recv_calls_per_request
        self.login_cookie_level = login_cookie_level

    def setConnectionSecurityParams(
        self,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        cafile: Optional[str] = None
    ) -> None:
        """
        Set up TLS parameters.

        :param certfile: The path to the server certificate file.
        :param keyfile: The path to the server private key file.
        :param cafile: The path to the CA certificate file.
        """
        # check values
        if self.security_params_set:
            raise RuntimeError("Connection security parameters can only be set once.")
        if (certfile is None) != (keyfile is None):
            raise ValueError("certfile and keyfile must both be provided or both be None.")
        if cafile is not None and certfile is None:
            raise ValueError("cafile can only be provided if certfile and keyfile are provided.\nThis means client authentication is enabled only if the server is able to present a certificate.")
        
        # check file paths
        if certfile and not (os.path.exists(certfile) and os.access(certfile, os.R_OK)):
            raise FileNotFoundError(f"Certificate file {certfile} does not exist or is not readable.")
        if keyfile and not (os.path.exists(keyfile) and os.access(keyfile, os.R_OK)):
            raise FileNotFoundError(f"Key file {keyfile} does not exist or is not readable.")
        if cafile and not (os.path.exists(cafile) and os.access(cafile, os.R_OK)):
            raise FileNotFoundError(f"CA file {cafile} does not exist or is not readable.")
        
        # create SSL context if necessary
        requireTLS = certfile is not None
        if requireTLS:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(certfile=certfile, keyfile=keyfile) # add the parameters so the server can present itself to the client
            if cafile:
                self.context.load_verify_locations(cafile=cafile) # add the CA file so the server can verify the client
                self.context.verify_mode = ssl.CERT_REQUIRED # require the client to present a certificate
            
            self.context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 # disable older protocols
        else:
            self.context = None
        self.security_params_set = True
        self.login_cookie_params = {"level": self.login_cookie_level, "use_tls": requireTLS}

    def startAPIServer(self) -> None:
        """Start the API server to accept connections."""
        if not self.security_params_set:
            raise RuntimeError("Connection security parameters must be set before starting the server.")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port)) # bind to the host and port
            server_socket.listen(5) # allow up to 5 connections in the queue
            server_socket.settimeout(0.5) # set a timeout for the accept call to 0.5 seconds
            if self.logger is not None:
                self.logger.info(f"Server listening on {self.host}:{self.port} {'with TLS' if (self.context is not None) else 'without TLS'}")
            
            # loop to accept connections
            self.mainLoopImpl(server_socket)

    def stopAPIServer(self) -> None:
        """Stop the API server."""
        if not self.SERVER_RUNNING:
            raise RuntimeError("Server is not running.")
        self.SERVER_RUNNING = False
    
    def isUsingTLS(self) -> bool:
        """Check if the server is using TLS."""
        return self.context is not None
    
    @abc.abstractmethod
    def mainLoopImpl(self, server_socket: socket.socket) -> None:
        """Main loop for the server to accept connections."""
        raise NotImplementedError("mainLoopImpl must be implemented in a subclass.")
    
    def generateSessionToken(self) -> str:
        return self.sessions.generateSessionToken()
    
    def getLoginParams(self) -> dict[str, str]:
        return self.login_cookie_params