# ClientWebAPI

**ClientWebAPI** is an installable NodeJS package written in TypeScript that serves as a client to connect and communicate with the Python-based ServerAPI. It acts as an intermediary communication layer between your NodeJS applications (or sub-servers) and the ServerAPI server, enabling secure and efficient interactions akin to a microservice architecture.

## Features

- **Authentication:** Simplified `.login()` and `.logout()` methods to manage sessions.
- **Custom Requests:** `.communicate()` method to send and receive JSON-based communications.
- **Secure Connections:** Supports both HTTP and HTTPS with optional TLS/SSL configurations.
- **Persistent Connections:** Utilizes HTTP/HTTPS agents with `keepAlive` for efficient communication.
- **TypeScript Support:** Written in TypeScript with strict type checking for enhanced reliability.
- **Error Handling:** Comprehensive error handling to manage various failure scenarios.
- **Modular Design:** Clean and maintainable code structure for easy integration.

## Installation

You can install **ClientWebAPI** using `npm`:

```bash
npm install path/to/clientwebapi.tgz
```

Note that for development using `TypeScript`, you need to install the official typing dependencies of NodeJS.
```bash
npm install --save-dev @types/node
```

## Usage

### Importing the APIClient

In your TypeScript or JavaScript project, import the `APIClient` class from the `clientwebapi` package:

```typescript
import { APIClient } from 'clientwebapi';
```

### Setting Up the Client

Initialize the `APIClient` with the necessary configuration options, set up security parameters (if using HTTPS), and perform authentication.

#### Example

```typescript
import { APIClient } from 'clientwebapi';
import * as fs from 'fs';

async function main() {
    // Initialize the APIClient with server details
    const client = new APIClient({
        host: '127.0.0.1',
        port: 8000,
        timeout: 5000, // Timeout in milliseconds (optional, default is 5000)
        maxBodyLength: 1048576, // Maximum body length in bytes (optional, default is 10MB)
    });

    // Optional: Set TLS/SSL parameters if the server requires HTTPS
    try {
        client.setConnectionSecurityParams({
            cert: fs.readFileSync('path/to/client/cert.pem', 'utf8'), // Optional, for client verification
            key: fs.readFileSync('path/to/client/key.pem', 'utf8'), // Optional, for client verification
            ca: fs.readFileSync('path/to/ca.pem', 'utf8') // To verify the server
        },
        true, 1); // Keep Alive and Max Sockets
    } catch (error) {
        console.error('Failed to set TLS parameters:', (error as Error).message);
        return;
    }

    try {
        // Login to the ServerAPI
        const loginResponse = await client.login('alice', 'password123');
        console.log('Login Response:', loginResponse);

        // Send a custom communication request
        const communicateResponse = await client.communicate({ action: 'echo', message: 'Hello, Server!' });
        console.log('Communicate Response:', communicateResponse);

        // Logout from the ServerAPI
        const logoutResponse = await client.logout();
        console.log('Logout Response:', logoutResponse);
    } catch (error) {
        console.error('Error:', (error as Error).message);
    }
}

main();
```

### Authentication

#### `login(username: string, password: string): Promise<RequestResponse>`

Logs in to the ServerAPI using the provided credentials.

- **Parameters:**
  - `username` (`string`): The username of the user.
  - `password` (`string`): The password of the user.

- **Returns:** 
  - `Promise<RequestResponse>`: Resolves to the server's JSON response upon successful login.

- **Usage:**

  ```typescript
  const response = await client.login('alice', 'password123');
  console.log(response.message); // "Login successful."
  ```

#### `logout(): Promise<RequestResponse>`

Logs out from the ServerAPI, invalidating the current session.

- **Parameters:** None.

- **Returns:** 
  - `Promise<RequestResponse>`: Resolves to the server's JSON response upon successful logout.

- **Usage:**

  ```typescript
  const response = await client.logout();
  console.log(response.message); // "Logout successful."
  ```

### Communicating with the Server

#### `communicate(data: Record<string, any>): Promise<RequestResponse>`

Sends a custom JSON request to the ServerAPI's `/communicate` endpoint and receives a JSON response based on your implementation.

- **Parameters:**
  - `data` (`Record<string, any>`): The JSON data to send to the server.

- **Returns:** 
  - `Promise<RequestResponse>`: Resolves to the server's JSON response.

- **Usage:**

  ```typescript
  const response = await client.communicate({ action: 'echo', message: 'Hello, Server!' });
  console.log(response.echo); // "Hello, Server!"
  ```

### Setting Connection Security Parameters

#### `securityParamsFromFilePath(caPath: string, certPath?: string, keyPath?: string): ConnectionSecurityParams: ConnectionSecurityParams`

Converts file paths to security parameters. Throws exceptions if the paths are invalid or when it is
unable to read from the path.

- **Parameters:**
  - `caPath` Path to the root trust certificate.
  - `certPath` Path to the client's own certificate to prove the identity of itself.
  - `keyPath` Path to the client's own private key.

- **Throws:**
  - `Error`: If some file reading operations has an error.

- **Usage:**

  ```typescript
  const securityParams = securityParamsFromFilePath("path/to/rootCAcert.pem");
  ```

#### `setConnectionSecurityParams(params: ConnectionSecurityParams, keepAlive: boolean=true, maxSockets: number=1): void`

Configures TLS/SSL parameters for secure HTTPS communication. This method **must** be called **before** making any requests and can **only** be called **once**.

- **Parameters:**
  - `params` (`ConnectionSecurityParams`): An object containing the following properties:
    - `cert` (`string`, optional): Path to the client's own SSL certificate file corresponding to the private key.
    - `key` (`string`, optional): Path to the client's own SSL private key file.
    - `ca` (`string`, optional): Path to the root CA certificate file for verifying the server's certificate.
  - `keepAlive` (`boolean`): Whether to use keep alive connections. Default true.
  - `maxSockets` (`boolean`): The maximum number of sockets that can be connected to the server at the same time.

- **Throws:**
  - `Error`: If exactly one of `cert` or `key` is provided (since they must be provided in pairs or completely not provided), or when `cert` or `key` is provided and `ca` is not (must give a root CA for TLS).
  - `Error`: If called more than once.

- **Usage:**

  ```typescript
  client.setConnectionSecurityParams({
      cert: fs.readFileSync('path/to/client/cert.pem', 'utf8'), // Optional
      key: fs.readFileSync('path/to/client/key.pem', 'utf8'), // Optional
      ca: fs.readFileSync('path/to/ca.pem', 'utf8')
  }, false, 2);
  ```

### APIClient Class Reference

#### Constructor

```typescript
constructor(options: APIClientOptions)
```

- **Parameters:**
  - `options` (`APIClientOptions`): Configuration options for initializing the client.
    - `host` (`string`): The server's hostname or IP address (e.g., `'127.0.0.1'`).
    - `port` (`number`): The server's port number (e.g., `8000`).
    - `timeout` (`number`, optional): Timeout for requests in milliseconds (default is `5000`).
    - `maxBodyLength` (`number`, optional): Maximum allowed length of response bodies in bytes (default is `10MB`).
    - `keepAliveMsecs` (`number`, optional): Maximum duration to keep the TCP socket alive (default is `30000`).

- **Usage:**

  ```typescript
  const client = new APIClient({
      host: '127.0.0.1',
      port: 8000,
      timeout: 5000, // Optional
      maxBodyLength: 1048576, // Optional
  });
  ```

#### Destroy

```typescript
destroy(): void
```

- **Parameters:**

- **Usage:**
Destroys the HTTP(S) agent, and makes the APIClient invalid.

  ```typescript
  client.destroy();
  ```

#### isUsingTLS

```typescript
isUsingTLS(): boolean
```

- **Parameters:**

- **Usage:**
Returns whether TLS is being used.

  ```typescript
  x = client.isUsingTLS();
  ```

### Error Handling

All methods in the `APIClient` class return promises that may reject with an `Error` object if the request fails or if the server responds with an error. It's essential to handle these errors appropriately to maintain the robustness of your application.

#### Example

```typescript
try {
    const loginResponse = await client.login('alice', 'password123');
    console.log('Login successful:', loginResponse.message);
} catch (error) {
    console.error('Login failed:', (error as Error).message);
}

try {
    const response = await client.communicate({ action: 'unknown' });
    console.log('Communicate response:', response);
} catch (error) {
    console.error('Communication error:', (error as Error).message);
}
```

### Persistent HTTP/HTTPS Connections (Keep-Alive)

To enhance performance by reusing TCP connections, **ClientWebAPI** utilizes HTTP/HTTPS agents with `keepAlive` enabled. This ensures that multiple requests can be sent over a single persistent connection, reducing the overhead of establishing new connections for each request.

- **Configuration:** Persistent connections are automatically managed when you set the connection security parameters using `setConnectionSecurityParams`. Simply set the keepAlive argument in the function.

- **No Additional Setup Required:** The client handles the agent configuration internally. Ensure that you do not create multiple instances of `APIClient` unnecessarily to maximize connection reuse.

### TypeScript Strictness

**ClientWebAPI** is written in TypeScript with strict type checking enabled. This enforces type safety and helps catch potential bugs during development. Ensure that your TypeScript configuration in your downstream project is compatible with strict type checking when using this package. You can either use TypeScript or JavaScript for downstream development.

## Example

A complete example integrating all aspects of the `APIClient` is provided below:

```typescript
import { APIClient, securityParamsFromFilePath } from 'ClientWebAPI';
import * as readline from 'readline';

/**
 * Creates a readline interface for reading input from stdin.
 */
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

/**
 * Promisified question function to ask questions via stdin.
 * @param query The question to prompt the user.
 * @returns A promise that resolves with the user's input.
 */
function question(query: string): Promise<string> {
    return new Promise(resolve => {
        rl.question(query, resolve);
    });
}

/**
 * Main function to run the testing script.
 */
async function main() {
    try {
        // Prompt user for server host
        const hostInput = await question('Enter server host (e.g., 127.0.0.1): ');
        const host = hostInput.trim();
        if (!host) {
            throw new Error('Host cannot be empty.');
        }

        // Prompt user for server port
        const portInput = await question('Enter server port (e.g., 8000): ');
        const port = parseInt(portInput.trim(), 10);
        if (isNaN(port) || port <= 0 || port > 65535) {
            throw new Error('Invalid port number.');
        }

        // Prompt user for keep-alive
        const keepAliveInput = await question('Keep the connection alive? (y/n): ');
        const keepAlive: boolean = keepAliveInput.trim().toLowerCase() === 'y';

        // Prompt user for max sockets
        const maxSocketsInput = await question('Enter the maximum number of sockets to use: ');
        let maxSockets: number = parseInt(maxSocketsInput.trim(), 10);
        maxSockets = isNaN(maxSockets) ? 1 : Math.max(Math.min(maxSockets, 10), 1); // Clamp between 1 and 10, and default to 1

        // Initialize the APIClient without TLS (HTTP)
        console.log(`Using the following settings:`);
        console.log(`Host: ${host}`);
        console.log(`Port: ${port}`);
        console.log(`KeepAlive: ${keepAlive}`);
        console.log(`MaxSockets: ${maxSockets}`);
        const client = new APIClient({
            host,
            port
        });
        const secParams = securityParamsFromFilePath(
            "/home/louis_ml/Desktop/TmpKeys/rootCA1.pem",
            "/home/louis_ml/Desktop/TmpKeys/key1_CA2.pem",
            "/home/louis_ml/Desktop/TmpKeys/key1.key"
        );
        //client.setConnectionSecurityParams(secParams, keepAlive, maxSockets);
        client.setConnectionSecurityParams({cert: undefined, key: undefined, ca: undefined}, keepAlive, maxSockets); // For testing without TLS

        console.log(`Set ServerAPI host as http://${host}:${port}`);
        console.log(`Using TLS: ${client.isUsingTLS()}`);

        // Display available commands
        console.log('\nAvailable commands:');
        console.log('1. login');
        console.log('2. logout');
        console.log('3. communicate');
        console.log('4. exit\n');

        rl.setPrompt('> ');
        rl.prompt();

        /**
         * Event listener for each line of input from the user.
         */
        rl.on('line', async (input: string) => {
            const command = input.trim().toLowerCase();

            switch (command) {
                case 'login':
                    await handleLogin(client);
                    break;
                case 'logout':
                    await handleLogout(client);
                    break;
                case 'communicate':
                    await handleCommunicate(client);
                    break;
                case 'exit':
                    console.log('Exiting the client. Goodbye!');
                    client.destroy();
                    rl.close();
                    return;
                default:
                    console.log('Unknown command. Please use one of the following: login, logout, communicate, exit');
            }

            rl.prompt();
        });

        /**
         * Event listener for closing the readline interface.
         */
        rl.on('close', () => {
            console.log('Client has been closed.');
            process.exit(0);
        });

    } catch (error) {
        console.error(`Error: ${(error as Error).message}`);
        rl.close();
    }
}

/**
 * Handles the login process by prompting the user for credentials.
 * @param client The APIClient instance.
 */
async function handleLogin(client: APIClient): Promise<void> {
    try {
        const username = await question('Enter username: ');
        const password = await question('Enter password: ');

        if (!username.trim() || !password.trim()) {
            console.log('Username and password cannot be empty.');
            return;
        }

        const response = await client.login(username.trim(), password.trim());
        console.log('Login successful:', response.jsonData);
    } catch (error) {
        console.error('Login failed:', (error as Error).message);
    }
}

/**
 * Handles the logout process.
 * @param client The APIClient instance.
 */
async function handleLogout(client: APIClient): Promise<void> {
    try {
        const response = await client.logout();
        console.log('Logout successful:', response.jsonData);
    } catch (error) {
        console.error('Logout failed:', (error as Error).message);
    }
}

/**
 * Handles the communication process by prompting the user for action and message.
 * @param client The APIClient instance.
 */
async function handleCommunicate(client: APIClient): Promise<void> {
    try {
        const action = await question('Enter action (e.g., echo): ');
        const message = await question('Enter message: ');

        if (!action.trim()) {
            console.log('Action cannot be empty.');
            return;
        }

        const data: Record<string, any> = { action: action.trim(), message: message.trim() };
        const response = await client.communicate(data);
        console.log('Communicate response:', response.jsonData);
    } catch (error) {
        console.error('Communication failed:', (error as Error).message);
    }
}

// Run the main function
main();
```


## IMPORTANT: Login status

The only thing that ClientWebAPI uses to check the status of the logins is whether the session token exists or not. This means that `/communicate` and `/logout` requests are sent regardless of the existence of the session token, and regardless of the validity of the session token in the server side.

If the session token does not exist, the cookie header will simply be not added to the HTTP request. Also, an invalid token (e.g expiry) with regards to the server may also be sent. Therefore, you should add code logic to "detect" and "handle" the cases where the tokens are expired and so on, as ClientWebAPI won't automatically handle the behaviour of relogging in.

Also, when logging in with a new `username, password` pair call `.logout()` before calling `.login()` if necessary.