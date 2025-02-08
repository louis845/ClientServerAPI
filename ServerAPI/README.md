# ServerAPI

ServerAPI is a minimalistic Python package designed to help you create an API server with a simple login mechanism and customizable behavior after successful authentication. It facilitates secure JSON-based communication, allowing downstream projects to define tailored responses based on their specific requirements.

## Features

- **Simple Login Mechanism:** Authenticate users using username and password credentials.
- **JSON-Based Communication:** Handle JSON requests and responses seamlessly.
- **Customizable Behavior:** Implement custom server responses via callback functions.
- **Threaded Server:** Manage multiple client connections concurrently using threading.
- **Session Management:** Securely manage user sessions with UUID-based tokens.
- **Optional TLS Support:** Enable secure communications using SSL/TLS.
- **Lightweight & Minimalistic:** Easy integration with minimal setup required.

## Installation

You can install ServerAPI using `pip`:

```bash
pip install git+ssh://git@ip.address/path/to/ServerAPI
```

## Usage

### Importing the ServerAPI

In your Python project, import the `ThreadedAPIServer` from the `ServerAPI` package:

```python
from ServerAPI import ThreadedAPIServer
```

### Setting Up the Server

Define your user credentials and implement the request callback function, then initialize and start the server.

#### Example

```python
import logging
from ServerAPI import ThreadedAPIServer

# Define user credentials
credentials = {
    "alice": "password123",
    "bob": "securepassword",
}

# Define the request callback function
def my_request_callback(username, session_token, data):
    """
    Handle authenticated requests.

    Args:
        username (str): The username of the authenticated user.
        session_token (str): The session token.
        data (dict): The JSON data sent by the client.

    Returns:
        tuple:
            force_close (bool): Whether to forcefully close the connection.
            force_logout (bool): Whether to force logout the user.
            response_json (dict): The JSON data to send back as the response.
    """
    # Implement your custom logic here
    if data.get("action") == "echo":
        response = {"echo": data.get("message", "")}
    else:
        response = {"error": "Unknown action."}
    
    # Do not force close or logout
    return (False, False, response)

# Set up logging
logger = logging.getLogger("MyAPIServer")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Initialize the server
server = ThreadedAPIServer(
    host="127.0.0.1",
    port=8000,
    credentials=credentials,
    request_callback=my_request_callback,
    login_cookie_level="Strict",  # Options: "None", "Lax", "Strict"
    logger=logger,
    timeout=5.0,
    max_recv_calls_per_request=1024
)

# Optional: Enable TLS
# server.setConnectionSecurityParams(certfile="path/to/cert.pem", keyfile="path/to/key.pem")

# Start the API server
try:
    server.startAPIServer()
except KeyboardInterrupt:
    server.stopAPIServer()
    logger.info("Server stopped.")
```

### API Endpoints

ServerAPI provides the following endpoints:

#### `/login` (POST)

Authenticate a user using username and password.

- **Request Body:**

  ```json
  {
      "username": "alice",
      "password": "password123"
  }
  ```

- **Response:**

  - **Success (200 OK):**

    ```json
    {
        "message": "Login successful."
    }
    ```

    Sets a `sessionToken` cookie in the response headers.

  - **Failure (400 Bad Request / 401 Unauthorized):**

    ```json
    {
        "error": "Invalid credentials."
    }
    ```

#### `/logout` (POST)

Logout the authenticated user.

- **Headers:**
  
  - `Cookie: sessionToken=<token>`

- **Response:**

  - **Success (200 OK):**

    ```json
    {
        "message": "Logout successful."
    }
    ```

  - **Failure (400 Bad Request / 401 Unauthorized):**

    ```json
    {
        "error": "Invalid session token."
    }
    ```

#### `/communicate` (POST)

Handle authenticated communication with custom behavior.

- **Headers:**

  - `Cookie: sessionToken=<token>`

- **Request Body:**

  Send a JSON payload as required by your application.

- **Response:**

  The response depends on the implementation of your `request_callback` function.

### Callbacks
Currently, only a multithreaded (in the same Python process) version can be used. As such, the `request_callback` is expected to be thread safe, since they may be run in difference threads.
In the future, there may be a `ProcessAPIServer` to execute the management of connections in subprocesses, and in such a case, `request_callback` should be process safe. However, `session_validity_callback`
will always be run in the main thread inside the main process.

### Customizing Behavior

Implement the `request_callback` function to define how the server should respond to authenticated requests. The callback receives the username, session token, and the JSON data sent by the client, and must return a tuple containing:

1. **force_close (bool):** Whether to forcefully close the connection after responding.
2. **force_logout (bool):** Whether to invalidate the user's session.
3. **response_json (dict):** The JSON data to send back as the response.

#### Example Callback

```python
def my_request_callback(username, session_token, data):
    # Example logic: Echo the received message
    message = data.get("message", "")
    response = {"echo": message}
    # Do not close or logout
    return (False, False, response)
```

### Enabling TLS

To secure communications using TLS, provide the server certificate and key files:

```python
server.setConnectionSecurityParams(certfile="path/to/cert.pem", keyfile="path/to/key.pem")
```

Optionally, specify a CA file for client certificate verification:

```python
server.setConnectionSecurityParams(certfile="path/to/cert.pem", keyfile="path/to/key.pem", cafile="path/to/ca.pem")
```

Ensure that `certfile`, `keyfile`, and `cafile` paths are correct and accessible.

## Configuration

### Credentials

Provide a dictionary mapping usernames to passwords when initializing the server:

```python
credentials = {
    "user1": "password1",
    "user2": "password2",
}
```

### Login Cookie Level

Set the security level for the session cookie:

- **"None":** No SameSite attribute.
- **"Lax":** SameSite=Lax.
- **"Strict":** SameSite=Strict.

Example:

```python
login_cookie_level="Strict"
```

### Logging

Provide a `logging.Logger` instance to capture server logs:

```python
import logging

logger = logging.getLogger("MyAPIServer")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
```

Pass the logger to the server:

```python
server = ThreadedAPIServer(..., logger=logger)
```

## API Reference

### `ThreadedAPIServer`

A threaded API server implementation.

#### `__init__`

```python
ThreadedAPIServer(
    host: str,
    port: int,
    credentials: dict[str, str],
    request_callback: Callable[[str, str, dict[str, Any]], tuple[bool, dict[str, Any]]],
    session_validity_callback: Optional[Callable[[LoginSession], bool]],
    login_cookie_level: str = "Strict",
    logger: Optional[logging.Logger] = None,
    timeout: float = 5.0,
    max_recv_calls_per_request: int = 1024
)
```

- **host:** The host address to bind the server (e.g., "127.0.0.1").
- **port:** The port number to listen on (e.g., 8000).
- **credentials:** A dictionary mapping usernames to passwords.
- **request_callback:** A function to handle authenticated requests. It receives `username`, `session_token`, and `data` as arguments and returns a tuple `(force_close, response_json)`. This function has to be thread and process safe.
- **session_validity_callback:** A function to invalidate LoginSession(s). This is called in the main server thread/process, so this function does not have to be assumed to thread/process safe.
- **login_cookie_level:** The security level for the session cookie. Options are `"None"`, `"Lax"`, or `"Strict"`.
- **logger:** An optional `logging.Logger` instance for logging server events.
- **timeout:** Socket timeout in seconds (default is 5.0).
- **max_recv_calls_per_request:** Maximum number of `recv` operations per request (default is 1024, corresponding to 4MB).

#### `setConnectionSecurityParams`

```python
setConnectionSecurityParams(
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    cafile: Optional[str] = None
) -> None
```

Set up TLS parameters.

- **certfile:** Path to the server's SSL certificate file.
- **keyfile:** Path to the server's SSL key file.
- **cafile:** (Optional) Path to the CA certificate file for client certificate verification.

#### `startAPIServer`

```python
startAPIServer() -> None
```

Start the API server to accept incoming connections.

#### `stopAPIServer`

```python
stopAPIServer() -> None
```

Stop the API server gracefully.

#### `isUsingTLS`

```python
isUsingTLS() -> bool
```

Check if the server is using TLS for secure communications.

## Security

To enable TLS, provide the necessary certificate and key files using `setConnectionSecurityParams`. Ensure that your certificates are securely managed and stored to maintain secure communications.

## IMPORTANT: Login status

The only thing that ServerAPI uses to check the status of the logins is whether the session token exists in the dictionary or not. Implement the callbacks correctly so they work as intended, and make appropriate use
of communication between callback functions that may be in different threads `ThreadedAPIServer` or in different processes `ProcessAPIServer` (not implemented yet).