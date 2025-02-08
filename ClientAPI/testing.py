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