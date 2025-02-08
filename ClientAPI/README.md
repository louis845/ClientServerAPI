# Python ClientAPI

**ClientAPI** is a Python library that serves as a client to connect and communicate with the ServerAPI server. It manages authentication, session management, and interactions with the server using HTTP or HTTPS connections. Designed with simplicity and efficiency in mind, ClientAPI leverages Python's built-in modules to provide a robust and easy-to-use interface for your applications.

## Features

- **Authentication:** Simplified `login` and `logout` methods to manage sessions.
- **Custom Requests:** `communicate` method to send and receive JSON-based communications.
- **Secure Connections:** Supports both HTTP and HTTPS with optional TLS/SSL configurations.
- **Persistent Connections:** Supports a keep-alive flag for persistent HTTP(S) connections.
- **Error Handling:** Comprehensive error handling to manage various failure scenarios.

## Installation

Since **ClientAPI** relies solely on Python's built-in modules, there are no external dependencies to install. Simply use the usual command:
```bash
pip install path/to/ClientAPI.whl
```

## Usage

### Importing the APIClient

In your Python project, import the `APIClient`, `ConnectionSecurityParams`, and `RequestResponse` classes from the `api_client` module:

```python
from ClientAPI import APIClient, ConnectionSecurityParams, RequestResponse
```

### Setting Up the Client

Initialize the `APIClient` with the necessary configuration options, set up security parameters (if using HTTPS), and perform authentication.

#### Example

```python
from ClientAPI import APIClient, ConnectionSecurityParams, RequestResponse
import json

def main():
    # Initialize the APIClient with server details
    client = APIClient(
        host='127.0.0.1',
        port=8000,
        timeout=5.0,  # Timeout in seconds (optional, default is 5.0 seconds)
        max_reads=1024  # Maximum reads per response. Default is 1024. Means 4096 * max_reads bytes.
    )
    # Optional: Set TLS/SSL parameters if the server requires HTTPS
    if use_TLS:
        sec_params = ConnectionSecurityParams(
            ca='path/to/rootCAcert.pem',
            cert='path/to/client_cert.pem',  # Optional
            key='path/to/client_key.pem'     # Optional
        )
    else:
        sec_params = ConnectionSecurityParams()
    client.set_connection_security_params(
        params=sec_params,
        keep_alive=True
    )

    try:
        # Login to the ServerAPI
        login_response = client.login('alice', 'password123')
        print('Login successful:', login_response.json_data)

        # Send a custom communication request
        communicate_response = client.communicate({'action': 'echo', 'message': 'Hello, Server!'})
        print('Communicate response:', communicate_response.json_data)

        # Logout from the ServerAPI
        logout_response = client.logout()
        print('Logout successful:', logout_response.json_data)
    except Exception as e:
        # if any one of the client steps fails, no matter due to TCP/TLS connections errors,
        # invalid credentials, invalid state or so on, an exception will be thrown.
        print('Error:', str(e))

    # Destroy the client
    client.destroy()

if __name__ == "__main__":
    main()
```

### Authentication

#### `login(username: str, password: str) -> RequestResponse`

Logs in to the ServerAPI using the provided credentials.

- **Parameters:**
  - `username` (`str`): The username of the user.
  - `password` (`str`): The password of the user.

- **Returns:** 
  - `RequestResponse`: The server's response containing the status code and JSON data.

- **Throws:** 
  - `Exception`: Whenever there is an error when processing the login request, including invalid credentials.

- **Usage:**

    ```python
    response = client.login('alice', 'password123')
    print(response.json_data)  # Example: {'message': 'Login successful.'}
    ```

#### `logout() -> RequestResponse`

Logs out from the ServerAPI, invalidating the current session, and *always* sets the internal session token to none.

- **Parameters:** None.

- **Returns:** 
  - `RequestResponse`: The server's response containing the status code and JSON data.

- **Throws:** 
  - `Exception`: Whenever there is an error when processing the logout request, including invalid states. The session token will be set to None no matter what.

- **Usage:**

    ```python
    response = client.logout()
    print(response.json_data)  # Example: {'message': 'Logout successful.'}
    ```

### Communicating with the Server

#### `communicate(data: dict[str, Any]) -> RequestResponse`

Sends a custom JSON request to the ServerAPI's `/communicate` endpoint and receives a JSON response.

- **Parameters:**
  - `data` (`dict[str, Any]`): The JSON data to send to the server.

- **Returns:** 
  - `RequestResponse`: The server's response containing the status code and JSON data.

- **Throws:** 
  - `Exception`: Whenever there is an error when processing the communicate request, including invalid states and so on.

- **Usage:**

    ```python
    response = client.communicate({'action': 'echo', 'message': 'Hello, Server!'})
    print(response.json_data)  # Example: {'echo': 'Hello, Server!'}
    ```

### Setting Connection Security Parameters

#### `ConnectionSecurityParams`

Holds the security parameters for establishing a secure connection. If all are None, TCP is used. Otherwise, TLS is used.

- **Attributes:**
  - `cert` (`Optional[str]`): Client certificate.
  - `key` (`Optional[str]`): Client private key.
  - `ca` (`Optional[str]`): Certificate Authority certificate.

#### `set_connection_security_params(params: ConnectionSecurityParams, keep_alive: bool = True) -> None`

Configures TLS/SSL parameters for secure HTTPS communication. This method **must** be called **before** making any requests and can **only** be called **once**.

- **Parameters:**
  - `params` (`ConnectionSecurityParams`): An object containing the following properties:
    - `cert` (`str`, optional): Client's SSL certificate.
    - `key` (`str`, optional): Client's SSL private key.
    - `ca` (`str`, optional): Root CA certificate for verifying the server's certificate.
  - ``keep_alive` (`bool`): Whether to use keep-alive connections. Defaults to `True`.`

- **Raises:**
  - `ValueError`: If exactly one of `cert` or `key` is provided, or if `ca` is missing when `cert` and `key` are provided.
  - `ValueError`: If called more than once.

- **Usage:**

    ```python
    client.set_connection_security_params(
        params=security_params,
        keep_alive=True
    )
    ```

## APIClient Class Reference

### Constructor

```python
APIClient(...)
```

- **Parameters:**
    - `host` (`str`): The server's hostname or IP address (e.g., `'127.0.0.1'`).
    - `port` (`int`): The server's port number (e.g., `8000`).
    - `timeout` (`float`, optional): Timeout for requests in seconds (default is `5.0`).
    - `max_reads` (`int`, optional):  Maximum reads per response. Default is 1024. Means 4096 * max_reads bytes.

- **Usage:**

    ```python
    from types import APIClientOptions

    client_options = APIClientOptions(
        host='127.0.0.1',
        port=8000,
        timeout=5000,  # Optional
        max_body_length=10 * 1024 * 1024  # Optional
    )
    client = APIClient(options=client_options)
    ```

### `destroy() -> None`

Destroys the client, closing any open connections.

- **Parameters:** None.

- **Usage:**

    ```python
    client.destroy()
    ```

## Error Handling

All methods in the `APIClient` class may raise exceptions if the request fails or if the server responds with an error. It's essential to handle these errors appropriately to maintain the robustness of your application.

#### Example

```python
try:
    response = client.login('alice', 'password123')
    print('Login successful:', response.json_data)
except Exception as e:
    print('Login failed:', str(e))

try:
    response = client.communicate({'action': 'unknown'})
    print('Communicate response:', response.json_data)
except Exception as e:
    print('Communication error:', str(e))
```

## Persistent HTTP/HTTPS Connections (Keep-Alive)

To enhance performance by reusing TCP connections, **ClientAPI** utilizes a mock HTTP client with `keep_alive` enabled. This ensures that multiple requests can be sent over a single persistent connection, reducing the overhead of establishing new connections for each request.

- **Configuration:** Persistent connections are managed by setting the `keep_alive` parameter in `set_connection_security_params`.
- **Behavior:** When `keep_alive` is `True`, a single persistent connection is maintained. If the server responds with `Connection: Close`, the connection is terminated.
- **Limitations:** The client manages a single connection, and multiplexing or handling multiple sockets is not supported.

## Example

A complete example integrating all aspects of the `APIClient` is provided below:

```python
import sys
sys.path.append("./src")
import json
from ClientAPI import APIClient, ConnectionSecurityParams, RequestResponse

def main():
    """
    Main function to run the testing script.
    """
    try:
        # Prompt user for server host
        host = input("Enter server host (e.g., 127.0.0.1): ").strip()
        if len(host) == 0:
            host = "127.0.0.1"
            print("Defaulting to 127.0.0.1")

        # Prompt user for server port
        port_input = input("Enter server port (e.g., 8080): ").strip()
        if len(port_input) == 0:
            port = 8080
            print("Defaulting to port 8080")
        else:
            try:
                port = int(port_input)
                if not (0 < port < 65536):
                    raise ValueError("Invalid port number.")
            except ValueError:
                raise

        # Prompt user for keep-alive
        keep_alive_input = input("Keep the connection alive? (y/n): ").strip().lower()
        keep_alive = keep_alive_input == "y"

        # Initialize the APIClient
        print("\nUsing the following settings:")
        print(f"Host: {host}")
        print(f"Port: {port}")
        print(f"KeepAlive: {keep_alive}")

        client = APIClient(
            host=host,
            port=port
        )

        # For testing without TLS
        security_params = ConnectionSecurityParams()
        client.set_connection_security_params(security_params, keep_alive=keep_alive)

        print(f"Set ServerAPI host as http://{host}:{port}")
        print(f"Using TLS: {security_params.requires_TLS()}")

        # Display available commands
        print("\nAvailable commands:")
        print("1. login")
        print("2. logout")
        print("3. communicate")
        print("4. exit\n")

        while True:
            command = input("> ").strip().lower()

            if command == "login":
                handle_login(client)
            elif command == "logout":
                handle_logout(client)
            elif command == "communicate":
                handle_communicate(client)
            elif command == "exit":
                print("Exiting the client. Goodbye!")
                client.destroy()
                sys.exit(0)
            else:
                print("Unknown command. Please use one of the following: login, logout, communicate, exit")

    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)

def handle_login(client: APIClient) -> None:
    """
    Handles the login process by prompting the user for credentials.

    Args:
        client (APIClient): The APIClient instance.
    """
    try:
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

        if not username or not password:
            print("Username and password cannot be empty.")
            return

        response = client.login(username, password)
        print("Login successful:", json.dumps(response.json_data, indent=2))
    except Exception as error:
        print("Login failed:", error)

def handle_logout(client: APIClient) -> None:
    """
    Handles the logout process.

    Args:
        client (APIClient): The APIClient instance.
    """
    try:
        response = client.logout()
        print("Logout successful:", json.dumps(response.json_data, indent=2))
    except Exception as error:
        print("Logout failed:", error)

def handle_communicate(client: APIClient) -> None:
    """
    Handles the communication process by prompting the user for action and message.

    Args:
        client (APIClient): The APIClient instance.
    """
    try:
        action = input("Enter action (e.g., echo): ").strip()
        message = input("Enter message: ").strip()

        if not action:
            print("Action cannot be empty.")
            return

        data = {"action": action, "message": message}
        response = client.communicate(data)
        print("Communicate response:", json.dumps(response.json_data, indent=2))
    except Exception as error:
        print("Communication failed:", error)

if __name__ == "__main__":
    main()
```

## Class Highlights

### `APIClient`

The core class for interacting with the ServerAPI server. It manages the connection, authentication, and communication processes.

- **Initialization:**
  - Requires `APIClientOptions` to set up the host, port, timeout, and maximum body length.
- **Methods:**
  - `set_connection_security_params`: Configures TLS/SSL parameters and connection behavior.
  - `login`: Authenticates the user with the server.
  - `logout`: Ends the user session.
  - `communicate`: Sends custom JSON data to the server.
  - `destroy`: Closes any open connections and invalidates the client.

### `ConnectionSecurityParams`

A helper class that encapsulates the security parameters required for establishing secure connections.

- **Attributes:**
  - `cert`: Client's SSL certificate.
  - `key`: Client's SSL private key.
  - `ca`: Certificate Authority certificate for verifying the server's certificate.

### `RequestResponse`

A simple data structure representing the server's response to API requests.

- **Attributes:**
  - `status_code` (`int`): HTTP status code returned by the server.
  - `json_data` (`Optional[dict]`): Parsed JSON data from the response body.

- **Usage:**

    ```python
    response = client.login('alice', 'password123')
    print(response.status_code)  # e.g., 200
    print(response.json_data)    # e.g., {'message': 'Login successful.'}
    ```

## IMPORTANT: Login status

The only thing that ClientAPI uses to check the status of the logins is whether the session token exists or not. This means that `/communicate` and `/logout` requests are sent regardless of the existence of the session token, and regardless of the validity of the session token in the server side.

If the session token does not exist, the cookie header will simply be not added to the HTTP request. Also, an invalid token (e.g expiry) with regards to the server may also be sent. Therefore, you should add code logic to "detect" and "handle" the cases where the tokens are expired and so on, as ClientAPI won't automatically handle the behaviour of relogging in.

Also, when logging in with a new `username, password` pair call `.logout()` before calling `.login()` if necessary.