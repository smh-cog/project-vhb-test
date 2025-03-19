// app.ts - Main application entry point

import * as express from 'express';
import * as bodyParser from 'body-parser';
import * as session from 'express-session';
import * as cookieParser from 'cookie-parser';
import userController from './userController';
import { logInfo, logError, handleError } from './logger';
import { deserializeUserData } from './validation';
import { defaultAdminUser } from './types';

const app = express();
const PORT = process.env.PORT || 3000;

// Vulnerability: Insecure session configuration
app.use(session({
  secret: 'keyboard cat', // Hardcoded session secret
  resave: true,
  saveUninitialized: true,
  cookie: {
    // Vulnerability: Missing security flags
    // httpOnly: true,
    // secure: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Vulnerability: Insecure cookie parser
app.use(cookieParser());

// Vulnerability: No body size limits
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Vulnerability: Missing security headers
// app.use(helmet());

// Vulnerability: CORS misconfiguration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Vulnerability: Insecure routes
app.use('/api/users', userController);

// Vulnerability: Insecure error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logError(`Global error handler: ${err.message}`, {
    stack: err.stack,
    url: req.url,
    method: req.method,
    body: req.body,
    headers: req.headers
  });
  
  // Vulnerability: Detailed error information exposed to client
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    path: req.url
  });
});

// Vulnerability: Insecure data parsing endpoint
app.post('/api/import', (req: express.Request, res: express.Response) => {
  try {
    const { data } = req.body;
    
    // Vulnerability: Insecure deserialization
    const parsedData = deserializeUserData(data);
    
    res.json({ success: true, data: parsedData });
  } catch (error) {
    handleError(error as Error);
    res.status(500).json({ error: 'Import failed' });
  }
});

// Vulnerability: Debug/development endpoint in production
app.get('/api/debug', (req: express.Request, res: express.Response) => {
  res.json({
    environment: process.env,
    adminUser: defaultAdminUser
  });
});

app.listen(PORT, () => {
  logInfo(`Server running on port ${PORT}`);
});

export default app;
