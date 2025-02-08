from typing import Optional, Any
import json
import traceback

from .types import ConnectionSecurityParams, RequestResponse
from .mock_http_client import MockHTTPClient
from .utils import parse_cookies

class APIClient:
    """
    APIClient is a client for interacting with the ServerAPI server.
    It handles authentication, session management, and communication with the server.
    """
    host: str
    port: int
    timeout: float
    max_reads: int
    
    security_params: Optional[ConnectionSecurityParams]
    session_token: Optional[str]
    client: Optional[MockHTTPClient]
    destroyed: bool

    def __init__(self,
                 host: str,
                 port: int,
                 timeout: float=5.0,
                 max_reads: int=1024):
        """
        Initializes the APIClient with the necessary configurations.

        Args:
            host (str): The server's hostname.
            port (int): The server's port.
            timeout (int): The request timeout in seconds. Default 5 seconds.
            max_reads (int): The maximum number of reads that can be performed. Default 1024.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_reads = max_reads

        self.security_params = None
        self.session_token = None
        self.client = None
        self.destroyed = False

    def set_connection_security_params(
        self,
        params: ConnectionSecurityParams,
        keep_alive: bool = True
    ) -> None:
        """
        Sets the connection security parameters for HTTPS communication.
        This method can only be called once.

        Args:
            params (ConnectionSecurityParams): Security parameters including cert, key, and ca.
            keep_alive (bool): Whether to keep the connection alive.

        Raises:
            ValueError: If input parameters are invalid or if security params are already set.
        """
        # check validity of the security parameters
        if self.security_params is not None:
            raise ValueError('Security parameters have already been set and cannot be modified.')
        params.check_valid()

        # set the security parameters and create the HTTP client
        self.security_params = params
        self.client = MockHTTPClient(
            host=self.host,
            port=self.port,
            security_params=params,
            keep_alive=keep_alive,
            timeout=self.timeout,
            max_reads=self.max_reads
        )

    def login(self, username: str, password: str) -> RequestResponse:
        """
        Logs in to the ServerAPI using the provided credentials.

        Args:
            username (str): The username.
            password (str): The password.

        Returns:
            RequestResponse: The server's response.

        Raises:
            Exception: If security parameters are not set or if the client is destroyed.
            ConnectionError: If some errors are due to the connection of the client.
        """
        self.ensure_security_params_set()

        data = json.dumps({"username": username, "password": password})
        response = self.make_request('/login', 'POST', data)
        return response

    def logout(self) -> RequestResponse:
        """
        Logs out from the ServerAPI, invalidating the current session.

        Returns:
            RequestResponse: The server's response.

        Raises:
            Exception: If security parameters are not set or if the client is destroyed.
            ConnectionError: If some errors are due to the connection of the client.
        """
        self.ensure_security_params_set()
        session_token = self.session_token
        self.session_token = None  # Clear session token no matter what
        response = self.make_request('/logout', 'POST', None, session_token)
        return response

    def communicate(self, data: dict[str, Any]) -> RequestResponse:
        """
        Sends a custom request to the ServerAPI's /communicate endpoint.

        Args:
            data (dict[str, Any]): The JSON data to send.

        Returns:
            RequestResponse: The server's response.

        Raises:
            Exception: If security parameters are not set or if the client is destroyed.
            ConnectionError: If some errors are due to the connection of the client.
        """
        self.ensure_security_params_set()
        payload = json.dumps(data)
        response = self.make_request('/communicate', 'POST', payload, self.session_token)
        return response

    def destroy(self) -> None:
        """
        Destroys the client, closing any open connections.
        """
        if self.client is not None:
            self.client.destroy()
        self.destroyed = True

    def ensure_security_params_set(self) -> None:
        """
        Ensures that security parameters have been set before making requests.

        Raises:
            Exception: If security parameters are not set or if the client is destroyed.
        """
        if not self.security_params or not self.client:
            raise Exception('Connection security parameters must be set before making requests.')
        if self.destroyed:
            raise Exception('This client has been destroyed and cannot be used.')

    def make_request(
        self,
        path: str,
        method: str,
        data: Optional[str] = None,
        session_token: Optional[str] = None
    ) -> RequestResponse:
        """
        Makes an HTTP/HTTPS request to the ServerAPI.

        Args:
            path (str): The API endpoint path.
            method (str): The HTTP method.
            data (Optional[str]): Optional JSON data to send.
            session_token (Optional[str]): The session token to include in the request.

        Returns:
            RequestResponse: The server's response.

        Raises:
            Exception: If the HTTP request fails.
        """
        if self.client is None:
            raise Exception('HTTP Client is not initialized.')

        headers = {}
        if data is not None:
            data_bytes = data.encode("utf-8") # convert to bytes
            headers['Content-Type'] = 'application/json'
            headers['Content-Length'] = str(len(data_bytes))
        else:
            data_bytes = None

        if session_token: # add session token to headers if provided
            headers['Cookie'] = f'sessionToken={session_token}'
        
        try:
            response = self.client.make_request(
                method=method,
                path=path,
                headers=headers,
                body=data_bytes
            )
        except Exception as e:
            raise ConnectionError("Request failed. Error message: {}".format(traceback.format_exc())) from e

        if path == '/login':
            # Set the cookie if the login request was successful, see if the header contains the cookie
            headers = response.get_headers()
            if (headers is not None) and ("set-cookie" in headers):
                cookies = headers["set-cookie"]
                cookies = parse_cookies(cookies)
                if "sessionToken" in cookies:
                    self.session_token = cookies["sessionToken"]
        
        # try to decode the response body as JSON
        json_data = None
        if response.body is not None:
            try:
                json_data = json.loads(response.body)
                if not isinstance(json_data, dict):
                    json_data = None
            except json.JSONDecodeError:
                pass
        
        # get the message from the JSON
        message = None
        if (json_data is not None) and (len(json_data) > 0):
            if "message" in json_data:
                message = json_data["message"]
            elif "error" in json_data:
                message = json_data["error"]
            else:
                first_key = next(iter(json_data.keys()))
                message = json_data[first_key]
        if message is None:
            try:
                message = response.body.decode("utf-8")
            except Exception:
                message = "No message provided from server."

        if 200 <= response.status_code < 300:
            return RequestResponse(response.status_code, json_data)
        else:
            raise ConnectionError(f"Request failed. Status Code: {response.status_code} Error message: {message}")