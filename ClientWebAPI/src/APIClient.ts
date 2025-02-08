import * as http from 'http';
import * as https from 'https';
import { ConnectionSecurityParams, APIClientOptions, RequestResponse } from './types';
import { parseCookies } from './utils';

/**
 * APIClient is a client for interacting with the ServerAPI server.
 * It handles authentication, session management, and communication with the server.
 */
export class APIClient {
    private host: string;
    private port: number;
    private timeout: number;
    private keepAliveMsecs: number;
    private maxBodyLength: number;
    private securityParams?: ConnectionSecurityParams;
    private sessionToken: string | null;
    private agent: http.Agent | https.Agent | null; // HTTPv1.1 or HTTPSv1.1 agent
    private keepAlive: boolean;

    private destroyed: boolean;

    /**
     * Initializes the APIClient with the necessary configurations.
     * @param options Configuration options for the client.
     */
    constructor(options: APIClientOptions) {
        this.host = options.host;
        this.port = options.port;
        this.timeout = options.timeout || 5000; // default 5 seconds
        this.maxBodyLength = options.maxBodyLength || 10 * 1024 * 1024; // default 10MB
        this.keepAliveMsecs = options.keepAliveMsecs || 30000; // default 30 seconds
        
        this.sessionToken = null;
        this.agent = null;
        this.destroyed = false;
        this.keepAlive = true;
    }

    /**
     * Sets the connection security parameters for HTTPS communication.
     * This method can only be called once.
     * @param params Security parameters including cert, key, and ca.
     * @param keepAlive Whether to keep the connection alive.
     * @param maxSockets The maximum number of sockets to use.
     */
    public setConnectionSecurityParams(
        params: ConnectionSecurityParams,
        keepAlive: boolean=true,
        maxSockets: number=1): void {
        // Validate input parameters
        if ((params.cert && !params.key) || (!params.cert && params.key)) {
            throw new Error("Both cert and key must be provided for secure connections, providing only one is not allowed.");
        }
        if (params.cert && !params.ca) { // it is permissible to give only CA but not others, to serve as verifying the server without client authentication
            throw new Error("CA certificate must be provided if cert and key are provided.");
        }

        if (this.securityParams) {
            throw new Error('Security parameters have already been set and cannot be modified.');
        }

        this.securityParams = params;
        this.keepAlive = keepAlive;
        if (params.ca) {
            // HTTPS with optional CA
            this.agent = new https.Agent({
                keepAlive: keepAlive,
                cert: params.cert,
                key: params.key,
                ca: params.ca,
                rejectUnauthorized: !!params.ca, // Verify server certificate if and only if CA is provided
                maxSockets: maxSockets,
                minVersion: 'TLSv1.3', // Highest TLS version
                keepAliveMsecs: this.keepAliveMsecs
            });
        } else {
            // HTTP
            this.agent = new http.Agent({
                keepAlive: keepAlive,
                maxSockets: maxSockets,
                keepAliveMsecs: this.keepAliveMsecs
            });
        }
    }

    /**
     * Returns whether the client is using TLS.
     * @returns Whether the client is using TLS.
     */
    public isUsingTLS(): boolean {
        return !!(this.securityParams!.ca)
    }

    /**
     * Logs in to the ServerAPI using the provided credentials.
     * @param username The username.
     * @param password The password.
     * @returns A promise that resolves to the server's response.
     */
    public async login(username: string, password: string): Promise<RequestResponse> {
        this.ensureSecurityParamsSet();

        const data = JSON.stringify({ username, password });
        const response = await this.makeRequest('/login', 'POST', null, data);
        return response;
    }

    /**
     * Logs out from the ServerAPI, invalidating the current session.
     * @returns A promise that resolves to the server's response.
     */
    public async logout(): Promise<RequestResponse> {
        this.ensureSecurityParamsSet();
        const sessionToken = this.sessionToken;
        this.sessionToken = null; // Clear session token no matter what.
        const response = await this.makeRequest('/logout', 'POST', sessionToken, undefined);
        return response;
    }

    /**
     * Sends a custom request to the ServerAPI's /communicate endpoint.
     * @param data The JSON data to send.
     * @returns A promise that resolves to the server's response.
     */
    public async communicate(data: Record<string, any>): Promise<RequestResponse> {
        this.ensureSecurityParamsSet();

        const payload = JSON.stringify(data);
        const response = await this.makeRequest('/communicate', 'POST', this.sessionToken, payload);
        return response;
    }

    /**
     * Destroys the client, closing any open connections.
     */
    public destroy(): void {
        if (this.agent) {
            this.agent.destroy();
        }
        this.destroyed = true;
    }

    /**
     * Ensures that security parameters have been set before making requests.
     */
    private ensureSecurityParamsSet(): void {
        if (!this.securityParams || !this.agent) {
            throw new Error('Connection security parameters must be set before making requests.');
        }
        if (this.destroyed) {
            throw new Error('This client has been destroyed and cannot be used.');
        }
    }

    /**
     * Makes an HTTP/HTTPS request to the ServerAPI.
     * @param path The API endpoint path.
     * @param method The HTTP method.
     * @param sessionToken The optional session token to include in the request.
     * @param data Optional JSON data to send.
     * @returns A promise that resolves to the server's response.
     */
    private makeRequest(path: string, method: string, sessionToken: string | null, data?: string): Promise<RequestResponse> {
        return new Promise((resolve, reject) => {
            if (!this.agent) {
                return reject(new Error('HTTP Agent is not initialized.'));
            }

            // Construct request options
            const isHTTPS = this.isUsingTLS();
            let headers: http.OutgoingHttpHeaders;
            if (data) {
                headers = {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(data)
                };
            } else {
                headers = {};
            }
            if (this.keepAlive) {
                headers['Connection'] = 'keep-alive';
            } else {
                headers['Connection'] = 'close';
            }
            const options: http.RequestOptions = {
                host: this.host,
                port: this.port,
                path: path,
                method: method,
                agent: this.agent,
                timeout: this.timeout,
                headers: headers
            };

            // Include sessionToken in headers if required
            if (sessionToken) { // If sessionToken is non null, include it in the headers
                options.headers!['Cookie'] = `sessionToken=${sessionToken}`;
            }

            const protocol = isHTTPS ? https : http;

            const req = protocol.request(options, (res: http.IncomingMessage) => {
                let rawData = '';
                res.setEncoding('utf8');

                res.on('data', (chunk: string) => {
                    rawData += chunk;
                    if (rawData.length > this.maxBodyLength) {
                        req.destroy();
                        reject(new Error('Response body exceeds maximum allowed length.'));
                    }
                });

                res.on('end', () => {
                    try {
                        const parsedData = JSON.parse(rawData);

                        // Handle Set-Cookie header to store session token
                        const setCookie = res.headers['set-cookie'];
                        if (setCookie && setCookie.length > 0 && path === '/login') {
                            // Assuming sessionToken is the first cookie
                            const cookies = parseCookies(setCookie[0]);
                            if (cookies['sessionToken']) {
                                this.sessionToken = cookies['sessionToken'];
                            }
                        }

                        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                            const response = new RequestResponse(res.statusCode, parsedData);
                            resolve(response);
                        } else {
                            reject(new Error(`Request failed. Status Code: ${res.statusCode} Body response: ${rawData}`));
                        }
                    } catch (e) {
                        reject(new Error(`Failed to parse server response as JSON in the client side. Server status code: ${res.statusCode}`));
                    }
                });
            });

            req.on('error', (e: Error) => {
                reject(e);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timed out.'));
            });

            if (data) {
                req.write(data);
            }

            req.end();
        });
    }
}