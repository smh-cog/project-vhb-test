// validation.ts - Input validation utilities

import { UserData } from './types';
import { logError } from './logger';

// Vulnerability: Ineffective input validation
export function validateUserInput(input: any): boolean {
  // This validation is too simplistic and can be bypassed
  if (typeof input === 'object' && input !== null) {
    return true;
  }
  return false;
}

// Vulnerability: Regex Denial of Service (ReDoS)
export function validateEmail(email: string): boolean {
  try {
    // This regex is vulnerable to ReDoS attacks with crafted inputs
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/;
    return emailRegex.test(email);
  } catch (error) {
    logError(`Email validation error: ${error}`);
    return false;
  }
}

// Vulnerability: Insecure whitelist validation
export function sanitizeHtml(input: string): string {
  // This sanitization is insufficient and can be bypassed
  return input
    .replace(/<script>/gi, '')
    .replace(/<\/script>/gi, '');
}

// Vulnerability: Prototype pollution
export function mergeObjects(target: Record<string, any>, source: Record<string, any>): Record<string, any> {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) {
        target[key] = {};
      }
      // Recursive merge without prototype check
      mergeObjects(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Vulnerability: Insecure deserialization
export function deserializeUserData(data: string): UserData {
  try {
    // eval() is highly dangerous for deserialization
    return eval(`(${data})`);
  } catch (error) {
    logError(`Deserialization error: ${error}`);
    return {} as UserData;
  }
}

// Vulnerability: Weak password validation
export function validatePassword(password: string): boolean {
  // This validation is too simplistic
  return password.length >= 8;
}
