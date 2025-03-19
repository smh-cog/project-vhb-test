// insecure-utils.ts - A collection of insecure patterns that would trigger CodeQL alerts

import * as fs from 'fs';
import * as cp from 'child_process';
import * as http from 'http';

// Vulnerability 1: SQL Injection
export function userLookupInsecure(userId: string): void {
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  // This is vulnerable to SQL injection if userId is not sanitized
  executeQuery(query);
}

// Vulnerability 2: Unsafe Command Execution
export function runCommand(command: string): void {
  // Executing commands directly from user input is dangerous
  cp.exec(command, (error, stdout, stderr) => {
    console.log('Command output:', stdout);
    console.log('Command errors:', stderr);
  });
}

// Vulnerability 3: Path Traversal
export function readUserFile(fileName: string): string {
  // Doesn't validate path, allowing access to any file on the system
  const filePath = `/var/user_files/${fileName}`;
  return fs.readFileSync(filePath, 'utf8');
}

// Vulnerability 4: Insecure Regular Expression
export function validateEmail(email: string): boolean {
  // This regex can cause ReDoS (Regular Expression Denial of Service)
  const emailRegex = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/;
  return emailRegex.test(email);
}

// Vulnerability 5: Hardcoded Credentials
export function connectToDatabase(): void {
  const username = 'admin';
  const password = 'password123'; // Hardcoded credentials
  console.log(`Connecting to database with ${username}:${password}`);
}

// Vulnerability 6: XSS (Cross-Site Scripting)
export function createUserProfile(name: string, bio: string): string {
  // Direct insertion of user input into HTML
  return `
    <div class="profile">
      <h2>${name}</h2>
      <p>${bio}</p>
    </div>
  `;
}

// Vulnerability 7: Insecure Deserialization
export function deserializeUserData(data: string): any {
  // Unsafe deserialization of user data
  return eval('(' + data + ')');
}

// Vulnerability 8: Insecure Cookie
export function setUserCookie(response: http.ServerResponse, userId: string): void {
  // Setting cookie without security flags
  response.setHeader('Set-Cookie', `userId=${userId}; path=/`);
}

// Vulnerability 9: Weak Random Number Generation
export function generateToken(): string {
  // Using Math.random() for security-critical token generation
  return Math.random().toString(36).substring(2, 15);
}

// Vulnerability 10: Potential Memory Leak
export class ResourceManager {
  private resources: any[] = [];
  
  public addResource(resource: any): void {
    this.resources.push(resource);
    // No method to remove resources, leading to potential memory leak
  }
}

// Dummy function to prevent compilation errors
function executeQuery(query: string): void {
  console.log(`Executing query: ${query}`);
}
