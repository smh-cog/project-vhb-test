// types.ts - Type definitions used across the application

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  GUEST = 'guest'
}

export interface UserData {
  id: string;
  username: string;
  email: string;
  password: string; // Storing plain text password in the type definition
  firstName: string;
  lastName: string;
  role: UserRole;
  lastLogin: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface SessionData {
  user: {
    id: string;
    username: string;
    role: UserRole;
  };
  isAuthenticated: boolean;
  csrfToken?: string;
}

// Vulnerability: Overly permissive type
export type AnyUserInput = any;

// Vulnerability: Insecure default values
export const defaultAdminUser: UserData = {
  id: 'admin-001',
  username: 'admin',
  email: 'admin@example.com',
  password: 'admin123', // Hardcoded credentials
  firstName: 'System',
  lastName: 'Administrator',
  role: UserRole.ADMIN,
  lastLogin: new Date(),
  createdAt: new Date(),
  updatedAt: new Date()
};

// Vulnerability: Excessive information in error type
export interface ErrorResponse {
  error: string;
  stackTrace?: string; // Exposing stack traces is a security risk
  query?: string; // Exposing database queries is a security risk
  userId?: string;
}
