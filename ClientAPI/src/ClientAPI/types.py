from typing import Optional
import os

class RequestResponse:
    """
    Represents the server's response to an API request.

    Attributes:
        status_code (int): HTTP status code returned by the server.
        json_data (Optional[dict]): Parsed JSON data from the response body.
    """
    def __init__(self, status_code: int, json_data: Optional[dict]):
        self.status_code = status_code
        self.json_data = json_data

class ConnectionSecurityParams:
    """
    Holds the security parameters for establishing a secure connection.

    Attributes:
        cert (Optional[str]): Client certificate.
        key (Optional[str]): Client private key.
        ca (Optional[str]): Certificate Authority certificate.
    """
    cert: Optional[str]
    key: Optional[str]
    ca: Optional[str]

    def __init__(self, cert: Optional[str] = None, key: Optional[str] = None, ca: Optional[str] = None):
        self.cert = cert
        self.key = key
        self.ca = ca

    def check_valid(self) -> None:
        """
        Checks the validity of the security parameters.

        Raises:
            ValueError: If the parameters are invalid.
        """
        if ((self.cert is None) and (self.key is not None)) or ((self.key is None) and (self.cert is not None)):
            raise ValueError("Both cert and key must be provided together, or neither.")
        if (self.cert is not None) and (self.ca is None):
            raise ValueError("CA certificate must be provided if cert is provided.")
        
        # check that the files exists and are readable
        if self.cert is not None:
            if (not os.path.isfile(self.cert)) or (not os.access(self.cert, os.R_OK)):
                raise FileNotFoundError(f"Client certificate file not found or not readable: {self.cert}")
        if self.key is not None:
            if (not os.path.isfile(self.key)) or (not os.access(self.key, os.R_OK)):
                raise FileNotFoundError(f"Client key file not found or not readable: {self.key}")
        if self.ca is not None:
            if (not os.path.isfile(self.ca)) or (not os.access(self.ca, os.R_OK)):
                raise FileNotFoundError(f"CA certificate file not found or not readable: {self.ca}")
    
    def requires_TLS(self) -> bool:
        """
        Checks if the security parameters require a secure connection.

        Returns:
            bool: True if a secure connection is required, False otherwise.
        """
        return self.ca is not None
