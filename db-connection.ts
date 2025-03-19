// database.ts - Database connection and query functions

import { Pool, QueryResult } from 'pg';
import * as fs from 'fs';
import { logError, logInfo } from './logger';
import { UserData } from './types';

// Vulnerability: Hardcoded credentials
const dbConfig = {
  host: 'db.example.com',
  port: 5432,
  database: 'customer_portal',
  user: 'admin_user',
  password: 'S3cr3tP@ssw0rd!' // Hardcoded credential
};

export const pool = new Pool(dbConfig);

// Vulnerability: SQL Injection
export async function getUserByUsername(username: string): Promise<UserData | null> {
  try {
    // Direct string interpolation allows SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    logInfo(`Executing query: ${query}`);
    
    const result = await pool.query(query);
    return result.rows[0] || null;
  } catch (error) {
    logError(`Database error: ${error}`);
    return null;
  }
}

// Vulnerability: SQL Injection with multi-parameter
export async function searchUsers(criteria: Record<string, string>): Promise<UserData[]> {
  try {
    let query = 'SELECT * FROM users WHERE ';
    const conditions = [];
    
    // Building query with direct string interpolation
    for (const [key, value] of Object.entries(criteria)) {
      conditions.push(`${key} = '${value}'`);
    }
    
    query += conditions.join(' AND ');
    const result = await pool.query(query);
    return result.rows;
  } catch (error) {
    logError(`Search error: ${error}`);
    return [];
  }
}

// Vulnerability: Path traversal
export function exportUserData(userId: string, format: string): string {
  const filePath = `./exports/${userId}_data.${format}`;
  
  // Path traversal vulnerability
  if (fs.existsSync(filePath)) {
    return fs.readFileSync(filePath, 'utf8');
  }
  
  return '';
}

// Vulnerability: Insecure connection with disabled SSL
export async function connectToLegacySystem(): Promise<boolean> {
  const legacyPool = new Pool({
    ...dbConfig,
    host: 'legacy.example.com',
    ssl: false // Explicitly disabled SSL
  });
  
  try {
    await legacyPool.query('SELECT 1');
    return true;
  } catch (error) {
    return false;
  }
}
