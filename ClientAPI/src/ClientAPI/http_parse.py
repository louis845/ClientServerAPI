from typing import Optional, Union
import socket
import ssl
import traceback

class HttpResponse:
    """
    Represents an HTTP/1.1 response.

    Attributes:
        version (str): HTTP version (should be 'HTTP/1.1').
        status_code (int): HTTP status code (e.g., 200, 404).
        reason_phrase (str): Reason phrase associated with the status code.
        headers (dict[str, str]): dictionary of HTTP headers.
        body (bytes): Response body.
        _error (Optional[str]): Error message if parsing failed.
    """
    version: Optional[str]
    status_code: Optional[int]
    reason_phrase: Optional[str]
    headers: Optional[dict[str, str]]  # header keys are translated to lowercase
    body: Optional[bytes]
    _error: Optional[str]
    
    def __init__(self):
        self.version = None
        self.status_code = None
        self.reason_phrase = None
        self.headers = None
        self.body = None
        self._error = None

    def hasError(self) -> bool:
        """Check if there was an error during parsing."""
        return self._error is not None

    def errorMsg(self) -> Optional[str]:
        """Get the error message if there was an error."""
        return self._error

    def get_version(self) -> Optional[str]:
        """Get the HTTP version."""
        if self.hasError():
            return None
        return self.version

    def get_status_code(self) -> Optional[int]:
        """Get the HTTP status code."""
        if self.hasError():
            return None
        return self.status_code

    def get_reason_phrase(self) -> Optional[str]:
        """Get the reason phrase associated with the status code."""
        if self.hasError():
            return None
        return self.reason_phrase

    def get_headers(self) -> Optional[dict[str, str]]:
        """Get the HTTP headers."""
        if self.hasError():
            return None
        return self.headers

    def get_header(self, key: str) -> Optional[str]:
        """Get a specific HTTP header."""
        if self.hasError() or self.headers is None:
            return None
        if key.lower() not in self.headers:
            return None
        return self.headers.get(key.lower())

    def get_body(self) -> Optional[bytes]:
        """Get the response body."""
        if self.hasError():
            return None
        return self.body
    
    def closing_requested(self) -> Optional[bool]:
        """Determine if the connection should be closed based on the 'Connection' header."""
        if self.hasError():
            return None
        connection = self.get_header("connection")
        if connection is None:
            return False
        return connection.lower() == "close"

def parse_http_response(sock: Union[socket.socket, ssl.SSLSocket],
                        max_reads: int) -> Optional[HttpResponse]:
    """
    Parse an HTTP/1.1 response from the given socket.

    Args:
        sock (socket.socket or ssl.SSLSocket): The TCP or TLS socket to read from.
        max_reads (int): The maximum number of times to read from the socket.

    Returns:
        Optional[HttpResponse]: An HttpResponse object if a response is successfully parsed,
                                None if no data is available yet (timeout on first read),
                                or an HttpResponse object with an error message if parsing failed.
    """
    BUFFER_SIZE = 4096  # Number of bytes to read at once
    HEADER_TERMINATOR = b'\r\n\r\n'
    buffer = bytearray()
    response = HttpResponse()
    reads = 0
    try:
        # Read until we have headers terminated by CRLF CRLF
        while HEADER_TERMINATOR not in buffer:
            try:
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk:
                    # Connection closed by server
                    if reads == 0:
                        return None
                    else:
                        response._error = "Connection closed by server before completing the response headers."
                        return response
                buffer.extend(chunk)
            except socket.timeout:
                if reads == 0:
                    # Timeout on first read means no data available yet
                    return None
                else:
                    # Timeout during reading headers
                    response._error = "Timeout occurred while reading the HTTP response headers."
                    return response
                
            reads += 1
            if (reads >= max_reads) and (HEADER_TERMINATOR not in buffer):
                # If max reads reached and headers not ended, return error
                response._error = "Maximum number of reads reached before completing the response headers."
                return response

        # Split headers and remaining buffer
        header_end = buffer.index(HEADER_TERMINATOR) + len(HEADER_TERMINATOR)
        header_bytes = buffer[:header_end]
        remaining = buffer[header_end:]

        # Decode headers
        try:
            header_text = header_bytes.decode('iso-8859-1')
        except UnicodeDecodeError:
            response._error = "Failed to decode HTTP headers."
            return response

        # Split response into lines
        lines = header_text.split("\r\n")
        if len(lines) < 1:
            response._error = "Empty HTTP response."
            return response

        # Parse status line
        status_line = lines[0]
        parts = status_line.split(' ', 2)  # Split into 3 parts: version, status_code, reason_phrase
        if len(parts) < 3:
            response._error = "Invalid HTTP response status line."
            return response
        version, status_code_str, reason_phrase = parts
        response.version = version

        # Validate HTTP version
        if version != "HTTP/1.1":
            response._error = f"Unsupported HTTP version: {version}."
            return response

        # Parse status code
        try:
            status_code = int(status_code_str)
            response.status_code = status_code
        except ValueError:
            response._error = f"Invalid status code: '{status_code_str}'."
            return response

        response.reason_phrase = reason_phrase.strip()

        # Parse headers
        headers = {}
        for header_line in lines[1:]:
            if header_line == '':
                continue  # Skip empty lines (shouldn't be any before HEADER_TERMINATOR)
            if ':' not in header_line:
                response._error = f"Invalid header format: '{header_line}'."
                return response
            key, value = header_line.split(':', 1)
            headers[key.strip().lower()] = value.strip()
        response.headers = headers

        # Determine if there is a body
        content_length = headers.get('content-length')
        if content_length is not None:
            try:
                body_length = int(content_length)
                if body_length < 0:
                    raise ValueError
            except ValueError:
                response._error = "Invalid Content-Length header."
                return response

            # Read the body from the remaining buffer, and the socket if necessary
            body = remaining
            bytes_needed = body_length - len(body)
            while bytes_needed > 0:
                try:
                    chunk = sock.recv(min(BUFFER_SIZE, bytes_needed))
                    if not chunk:
                        response._error = "Connection closed by server while reading the body."
                        return response
                    body.extend(chunk)
                    bytes_needed -= len(chunk)
                except socket.timeout:
                    response._error = "Timeout occurred while reading the HTTP response body."
                    return response
                reads += 1
                if (reads >= max_reads) and (bytes_needed > 0):
                    # If max reads reached and body not complete, return error
                    response._error = "Maximum number of reads reached before completing the response body."
                    return response

            response.body = bytes(body[:body_length])
        else:
            # No body; for responses, certain status codes should not have a body
            # Typically, 1xx, 204, and 304 should not have a body
            no_body_statuses = {100, 101, 102, 103, 204, 304}
            if response.status_code not in no_body_statuses:
                response._error = "Missing Content-Length header for response that should have a body."
                return response
            response.body = None

        return response

    except Exception as e:
        # Catch all unexpected exceptions and store traceback
        response._error = ''.join(traceback.format_exception_only(type(e), e)).strip()
        return response