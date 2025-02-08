import { APIClient } from './APIClient';
import { securityParamsFromFilePath } from './types';
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