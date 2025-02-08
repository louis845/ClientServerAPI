from typing import Any, Callable, Optional
import sys
sys.path.append("./src")
import ServerAPI
import logging

def on_request(username: str,
               session_token: str,
               data: Any) -> tuple[bool, dict[str, Any]]:
    return False, {"response": "Hello, world!", "username": username, "echo": data}

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    credentials = {"admin": "password", "user": "password", "user2": "password"}

    # Create a custom logger
    logger = logging.getLogger("ServerAPILogger")
    logger.setLevel(logging.DEBUG)

    # Create handlers
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)

    # Create formatters and add them to handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(console_handler)

    server = ServerAPI.ThreadedAPIServer(
        host=host, port=port, credentials=credentials,
        request_callback=on_request,
        logger=logger
    )
    server.setConnectionSecurityParams() # use plain TCP
    """server.setConnectionSecurityParams(certfile="/home/louis_ml/Desktop/TmpKeys/key1_CA1.pem",
                                       keyfile="/home/louis_ml/Desktop/TmpKeys/key1.key",
                                       cafile="/home/louis_ml/Desktop/TmpKeys/rootCA1.pem")"""
    server.startAPIServer()