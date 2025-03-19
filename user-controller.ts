// userController.ts - User management controller

import * as express from 'express';
import * as crypto from 'crypto';
import { exec } from 'child_process';
import { getUserByUsername, searchUsers, exportUserData } from './database';
import { validateUserInput } from './validation';
import { UserData, UserRole } from './types';
import { logInfo, logError } from './logger';

export const router = express.Router();

// Vulnerability: Command injection
router.post('/export-pdf', async (req: express.Request, res: express.Response) => {
  const { userId, templateId } = req.body;
  
  try {
    // Command injection vulnerability
    const command = `node pdf-generator.js --user ${userId} --template ${templateId}`;
    exec(command, (error, stdout, stderr) => {
      if (error) {
        logError(`PDF generation error: ${error.message}`);
        return res.status(500).json({ error: 'Failed to generate PDF' });
      }
      
      res.json({ success: true, output: stdout });
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerability: Insecure authentication
router.post('/login', async (req: express.Request, res: express.Response) => {
  const { username, password } = req.body;
  
  try {
    const user = await getUserByUsername(username);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Insecure password comparison (timing attack vulnerability)
    if (password === user.password) {
      // Vulnerability: Insecure session management
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };
      
      return res.json({ success: true, user: req.session.user });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerability: Insecure direct object reference (IDOR)
router.get('/profile/:userId', async (req: express.Request, res: express.Response) => {
  const { userId } = req.params;
  
  try {
    // No authorization check, allowing access to any user's data
    const user = await searchUsers({ id: userId });
    
    if (!user || user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user: user[0] });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerability: Weak cryptography
router.post('/reset-password', async (req: express.Request, res: express.Response) => {
  const { username } = req.body;
  
  try {
    const user = await getUserByUsername(username);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Vulnerability: Weak random token generation
    const resetToken = Math.random().toString(36).substring(2, 15);
    
    // Vulnerability: Insecure hashing algorithm
    const hashedToken = crypto.createHash('md5').update(resetToken).digest('hex');
    
    // Store token and send email logic would go here
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerability: XSS through unvalidated file download
router.get('/download/:filename', (req: express.Request, res: express.Response) => {
  const { filename } = req.params;
  
  try {
    // Path traversal vulnerability
    const fileContent = exportUserData(req.session.user.id, filename);
    
    // Content-disposition header missing, allowing XSS
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(fileContent);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
