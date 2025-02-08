import socket
import ssl
from typing import Optional, Union

from .http_parse import parse_http_response, HttpResponse
from .types import ConnectionSecurityParams

STATUS_CODES: dict[int, str] = {}

def send_http_request(
    sock: Union[socket.socket, ssl.SSLSocket],
    method: str,
    path: str,
    headers: dict[str, str],
    body: Optional[bytes] = None
) -> None:
    """
    Constructs and sends an HTTP/1.1 request over the provided socket.

    Args:
        sock (Union[socket.socket, ssl.SSLSocket]): The socket to send the request through.
        method (str): The HTTP method (e.g., GET, POST).
        path (str): The request path (e.g., /index.html).
        headers (dict[str, str]): A dictionary of HTTP headers.
        body (Optional[bytes]): The request body as bytes. Defaults to None.
    """
    # Start with the request line
    request_line = f"{method.upper()} {path} HTTP/1.1\r\n"

    # Ensure headers keys are case-insensitive
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Ensure the Host header is present
    if 'host' not in headers_lower:
        raise ValueError("Host header is required in HTTP/1.1 requests")

    # If a body is present, set the Content-Length header
    if body is not None:
        headers_lower['content-length'] = str(len(body))
    else:
        # For methods that typically do not have a body, Content-Length can be omitted
        # However, for consistency, set Content-Length to '0' if the method allows a body
        if method.upper() in ['POST', 'PUT', 'PATCH']:
            headers_lower['content-length'] = '0'

    # Ensure the Connection header is set to keep the connection alive by default
    if 'connection' not in headers_lower:
        headers_lower['connection'] = 'keep-alive'

    # Construct the headers section
    headers_section = ""
    for key, value in headers_lower.items():
        # Capitalize header keys for standard formatting
        header_key = '-'.join([word.capitalize() for word in key.split('-')])
        headers_section += f"{header_key}: {value}\r\n"

    # End headers with an additional CRLF
    headers_section += "\r\n"

    # Combine request line and headers
    request = request_line + headers_section
    request_bytes = request.encode('iso-8859-1')

    # Append body if present
    if body:
        request_bytes += body

    # Send the request
    sock.sendall(request_bytes)

class MockHTTPClient:
    """
    MockHTTPClient emulates HTTP request behavior with support for keep-alive connections.
    """
    host: str
    port: int
    security_params: ConnectionSecurityParams
    keep_alive: bool
    timeout: float
    max_reads: int

    sock: Optional[Union[socket.socket, ssl.SSLSocket]]
    tls_context: Optional[ssl.SSLContext]

    def __init__(
        self,
        host: str,
        port: int,
        security_params: ConnectionSecurityParams,
        keep_alive: bool = True,
        timeout: float = 5.0,
        max_reads: int = 1024
    ):
        """
        Initializes the MockHTTPClient with connection parameters.

        Args:
            host (str): Server host address.
            port (int): Server port number.
            security_params (ConnectionSecurityParams): Security parameters for TLS.
            keep_alive (bool): Whether to maintain a persistent connection.
            timeout (float): Request timeout in seconds. Defaults to 5.0 seconds.
            max_reads (int): Maximum allowed length for response bodies in bytes. Defaults to 1024.
        """
        self.host = host
        self.port = port
        self.security_params = security_params
        self.keep_alive = keep_alive
        self.timeout = timeout
        self.max_reads = max_reads

        self.sock = None
        self.tls_context = None

        # create default context for TLS, if necessary
        self.security_params.check_valid()
        if self.security_params.requires_TLS():
            self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.tls_context.load_verify_locations(cafile=self.security_params.ca) # add the CA file so the client can verify the server
            self.tls_context.verify_mode = ssl.CERT_REQUIRED
            if self.security_params.cert is not None:
                self.tls_context.load_cert_chain(certfile=self.security_params.cert, keyfile=self.security_params.key) # add the parameters so the client can present itself to the server
            
            self.tls_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 # disable older protocols

    def _create_connection(self) -> None:
        """
        Creates and initializes a socket connection to the server. Raises various errors and exceptions if the connection fails.
        """
        run_success = False
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create TCP socket
            self.sock.settimeout(self.timeout) # set the timeout for the socket
            if self.security_params.requires_TLS(): # wrap the socket in an SSL context, if necessary
                self.sock = self.tls_context.wrap_socket(self.sock, server_hostname=self.host)
            self.sock.connect((self.host, self.port)) # connect to the server
            run_success = True
        finally: # we do not catch exceptions here
            if not run_success: # however, if we failed, we need to clean up
                if self.sock is not None:
                    try:
                        self.sock.close()
                    except Exception:
                        pass
                    self.sock = None

    def _close_connection(self) -> None:
        """
        Closes the current socket connection.
        """
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def make_request(self,
                     method: str,
                     path: str,
                     headers: dict[str, str],
                     body: Optional[bytes]) -> HttpResponse:
        """
        Sends an HTTP request and returns the parsed HTTP response. Raises various errors and exceptions if the request fails.
        This method ensures the internal states are consistent and cleaned up properly.

        Args:
            method (str): HTTP method (e.g., 'GET', 'POST').
            path (str): Request path (e.g., '/login').
            headers (dict[str, str]): Dictionary of HTTP headers.
            body (Optional[bytes]): Request body as bytes.

        Returns:
            HttpResponse: Parsed HTTP response.

        Raises:
            Various exceptions if the request fails.
        """
        trials = 0
        max_trials = 2 if self.keep_alive else 1 # a single trial for non-keep alive, two for keep-alive since we may need to retry once if the previous connection is broken

        # add additional things to the headers
        headers = headers.copy()
        if "host" not in [key.lower() for key in headers.keys()]: # add the host header if it is not present
            headers["Host"] = self.host
        if not self.keep_alive: # add the connection header if it is not keep-alive
            headers["Connection"] = "close"

        # send the request and get the response within the maximum number of trials
        while True:
            try:
                if self.sock is None: # create a new connection if necessary
                    self._create_connection()
                
                send_http_request(self.sock, method, path, headers, body) # send the request

                # get response
                response = parse_http_response(self.sock, max_reads=self.max_reads)  # Max reads to prevent infinite loop, 4096 * max_reads bytes, = 4 MB default (max_reads=1024)
                if response is None:
                    raise ConnectionError("Connection closed or timeout when reading response.") # we expect immediate data / within some timeout timeframe, so if we get None, we have a problem.
                if response.hasError():
                    raise ConnectionError("Failed to parse response. Error: {}".format(response.errorMsg()))
                break # success, break the loop
            except Exception as e:
                trials += 1
                self._close_connection() # we cleanup the connection if we failed to send the request or get the response, before going on to the next trial, or returning due to max trials
                if trials == max_trials: # we have tried the maximum number of times
                    raise # re-raise the original exception
        
        # check if the connection should be closed
        if response.closing_requested() or not self.keep_alive:
            self._close_connection()

        return response

    def destroy(self) -> None:
        self._close_connection()