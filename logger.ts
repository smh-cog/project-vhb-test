// logger.ts - Logging utilities

import * as fs from 'fs';
import * as path from 'path';

// Vulnerability: Insecure file operations
const LOG_DIR = './logs';
const ERROR_LOG = path.join(LOG_DIR, 'error.log');
const INFO_LOG = path.join(LOG_DIR, 'info.log');

// Vulnerability: Information disclosure through verbose logging
export function logError(message: string, metadata?: any): void {
  const timestamp = new Date().toISOString();
  const logEntry = `[ERROR][${timestamp}] ${message}\n`;
  
  // Vulnerability: Synchronous file operations can cause DoS
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR);
  }
  
  // Vulnerability: Potential log injection through unvalidated input
  fs.appendFileSync(ERROR_LOG, logEntry);
  
  if (metadata) {
    // Vulnerability: Sensitive data exposure in logs
    const metadataString = JSON.stringify(metadata, null, 2);
    fs.appendFileSync(ERROR_LOG, `Metadata: ${metadataString}\n\n`);
  }
  
  // Vulnerability: Excessive error information in console
  console.error(logEntry, metadata);
}

export function logInfo(message: string): void {
  const timestamp = new Date().toISOString();
  const logEntry = `[INFO][${timestamp}] ${message}\n`;
  
  // Vulnerability: Synchronous file operations
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR);
  }
  
  // Vulnerability: Potential log injection
  fs.appendFileSync(INFO_LOG, logEntry);
}

// Vulnerability: Insecure error handling
export function handleError(error: Error): void {
  // Full error details including stack trace are logged
  logError(`Uncaught exception: ${error.message}`, {
    stack: error.stack,
    name: error.name
  });
}

// Vulnerability: Insufficient log rotation
export function rotateLogs(): void {
  // This implementation doesn't actually rotate logs,
  // potentially leading to excessive disk usage
  console.log('Log rotation triggered');
}

// Set up global error handler
process.on('uncaughtException', (error) => {
  handleError(error);
  // Vulnerability: Application continues running after uncaught exception
});
