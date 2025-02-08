import * as fs from 'fs';

export class RequestResponse {
    statusCode: number;
    jsonData: any | null;

    constructor(
        statusCode: number,
        jsonData: any | null
    ) {
        this.statusCode = statusCode;
        this.jsonData = jsonData;
    }
}

export interface ConnectionSecurityParams {
    cert?: string;
    key?: string;
    ca?: string;
}

export interface APIClientOptions {
    host: string;
    port: number;
    timeout?: number; // in milliseconds
    keepAliveMsecs?: number; // in milliseconds
    maxBodyLength?: number; // in bytes
}

export function securityParamsFromFilePath(caPath: string, certPath?: string, keyPath?: string): ConnectionSecurityParams {
    const securityParams: ConnectionSecurityParams = {};

    if (certPath) {
        if (!fs.existsSync(certPath) || !fs.lstatSync(certPath).isFile()) {
            throw new Error(`Certificate file not found at path: ${certPath}`);
        }
        fs.accessSync(certPath, fs.constants.R_OK); // Check if the file is readable
        securityParams.cert = fs.readFileSync(certPath, 'utf-8');
    }

    if (keyPath) {
        if (!fs.existsSync(keyPath) || !fs.lstatSync(keyPath).isFile()) {
            throw new Error(`Key file not found at path: ${keyPath}`);
        }
        fs.accessSync(keyPath, fs.constants.R_OK); // Check if the file is readable
        securityParams.key = fs.readFileSync(keyPath, 'utf-8');
    }

    if (caPath) {
        if (!fs.existsSync(caPath) || !fs.lstatSync(caPath).isFile()) {
            throw new Error(`CA file not found at path: ${caPath}`);
        }
        fs.accessSync(caPath, fs.constants.R_OK); // Check if the file is readable
        securityParams.ca = fs.readFileSync(caPath, 'utf-8');
    }

    return securityParams;
}