const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Master Key for password recovery
const MASTER_KEY = process.env.MASTER_KEY || 'master@2026';

app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

const DATA_DIR = path.join(__dirname, 'data');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');

async function ensureDataDir() {
    try {
        await fs.access(DATA_DIR);
    } catch {
        await fs.mkdir(DATA_DIR, { recursive: true });
    }
}

async function loadAdmin() {
    await ensureDataDir();
    try {
        const data = await fs.readFile(ADMIN_FILE, 'utf8');
        return JSON.parse(data);
    } catch {
        const defaultAdmin = {
            username: process.env.ADMIN_USERNAME || 'DebDas',
            password: process.env.ADMIN_PASSWORD || 'master'
        };
        await fs.writeFile(ADMIN_FILE, JSON.stringify(defaultAdmin, null, 2));
        return defaultAdmin;
    }
}

async function saveAdmin(admin) {
    await ensureDataDir();
    await fs.writeFile(ADMIN_FILE, JSON.stringify(admin, null, 2));
}

async function loadKeys() {
    await ensureDataDir();
    try {
        const data = await fs.readFile(KEYS_FILE, 'utf8');
        return JSON.parse(data);
    } catch {
        await fs.writeFile(KEYS_FILE, JSON.stringify([], null, 2));
        return [];
    }
}

async function saveKeys(keys) {
    await ensureDataDir();
    await fs.writeFile(KEYS_FILE, JSON.stringify(keys, null, 2));
}

function generateAccessKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let key = 'key_';
    for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}

const requireAuth = (req, res, next) => {
    if (req.session && req.session.isAuthenticated) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// Error page (index.html)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Main panel (view.html)
app.get('/view.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        const admin = await loadAdmin();
        if (username === admin.username && password === admin.password) {
            req.session.isAuthenticated = true;
            req.session.username = username;
            res.json({ success: true });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Auth status
app.get('/api/auth/status', (req, res) => {
    res.json({ authenticated: req.session.isAuthenticated || false });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

// Master Key - View admin credentials or reset password
app.post('/api/master-recovery', async (req, res) => {
    try {
        const { masterKey, action, newPassword } = req.body;
        
        if (masterKey !== MASTER_KEY) {
            return res.status(401).json({ error: 'Invalid master key' });
        }
        
        const admin = await loadAdmin();
        
        if (action === 'view') {
            // View admin credentials
            res.json({ 
                success: true, 
                admin: admin 
            });
        } else if (action === 'reset' && newPassword) {
            // Reset password
            if (newPassword.length < 6) {
                return res.status(400).json({ error: 'Password must be at least 6 characters' });
            }
            admin.password = newPassword;
            await saveAdmin(admin);
            res.json({ success: true, message: 'Password reset successfully' });
        } else {
            res.status(400).json({ error: 'Invalid action' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Recovery failed' });
    }
});

// Change password
app.post('/api/change-password', requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;
        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ error: 'All fields required' });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        const admin = await loadAdmin();
        if (currentPassword !== admin.password) {
            return res.status(401).json({ error: 'Current password incorrect' });
        }
        admin.password = newPassword;
        await saveAdmin(admin);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Get keys
app.get('/api/keys', requireAuth, async (req, res) => {
    try {
        const keys = await loadKeys();
        res.json(keys);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load keys' });
    }
});

// Create key
app.post('/api/keys', requireAuth, async (req, res) => {
    try {
        const { name, botToken, chatId, days } = req.body;
        if (!name || !botToken || !chatId || !days) {
            return res.status(400).json({ error: 'All fields required' });
        }
        const keys = await loadKeys();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + parseInt(days));
        const newKey = {
            id: uuidv4(),
            name: name.trim(),
            accessKey: generateAccessKey(),
            botToken: botToken.trim(),
            chatId: chatId.trim(),
            createdAt: new Date().toISOString(),
            expiresAt: expiresAt.toISOString(),
            isActive: true
        };
        keys.push(newKey);
        await saveKeys(keys);
        res.status(201).json(newKey);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create key' });
    }
});

// Extend key
app.put('/api/keys', requireAuth, async (req, res) => {
    try {
        const { accessKey } = req.body;
        if (!accessKey) {
            return res.status(400).json({ error: 'Access key required' });
        }
        const keys = await loadKeys();
        const keyIndex = keys.findIndex(k => k.accessKey === accessKey);
        if (keyIndex === -1) {
            return res.status(404).json({ error: 'Key not found' });
        }
        const currentExpiry = new Date(keys[keyIndex].expiresAt);
        const now = new Date();
        const baseDate = currentExpiry > now ? currentExpiry : now;
        const newExpiry = new Date(baseDate);
        newExpiry.setDate(newExpiry.getDate() + 30);
        keys[keyIndex].expiresAt = newExpiry.toISOString();
        keys[keyIndex].updatedAt = new Date().toISOString();
        await saveKeys(keys);
        res.json({ success: true, expiresAt: newExpiry.toISOString() });
    } catch (error) {
        res.status(500).json({ error: 'Failed to extend key' });
    }
});

// Update key
app.put('/api/keys/update', requireAuth, async (req, res) => {
    try {
        const { accessKey, name, botToken, chatId, expiresAt } = req.body;
        if (!accessKey) {
            return res.status(400).json({ error: 'Access key required' });
        }
        const keys = await loadKeys();
        const keyIndex = keys.findIndex(k => k.accessKey === accessKey);
        if (keyIndex === -1) {
            return res.status(404).json({ error: 'Key not found' });
        }
        if (name) keys[keyIndex].name = name.trim();
        if (botToken) keys[keyIndex].botToken = botToken.trim();
        if (chatId) keys[keyIndex].chatId = chatId.trim();
        if (expiresAt) keys[keyIndex].expiresAt = new Date(expiresAt).toISOString();
        keys[keyIndex].updatedAt = new Date().toISOString();
        await saveKeys(keys);
        res.json({ success: true, key: keys[keyIndex] });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update key' });
    }
});

// Delete key
app.delete('/api/keys', requireAuth, async (req, res) => {
    try {
        const { key } = req.query;
        if (!key) {
            return res.status(400).json({ error: 'Key required' });
        }
        const keys = await loadKeys();
        const filteredKeys = keys.filter(k => k.accessKey !== key);
        if (filteredKeys.length === keys.length) {
            return res.status(404).json({ error: 'Key not found' });
        }
        await saveKeys(filteredKeys);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete key' });
    }
});

// Send message
app.post('/api/send', async (req, res) => {
    try {
        const { accessKey, message } = req.body;
        if (!accessKey || !message) {
            return res.status(400).json({ error: 'Access key and message required' });
        }
        const keys = await loadKeys();
        const keyData = keys.find(k => k.accessKey === accessKey);
        if (!keyData) {
            return res.status(404).json({ error: 'Invalid access key' });
        }
        if (new Date() > new Date(keyData.expiresAt)) {
            return res.status(403).json({ error: 'Access key expired' });
        }
        const response = await axios.post(`https://api.telegram.org/bot${keyData.botToken}/sendMessage`, {
            chat_id: keyData.chatId,
            text: message,
            parse_mode: 'HTML'
        });
        res.json({ success: true, telegram: response.data });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Health
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK' });
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Start server
app.listen(PORT, async () => {
    await ensureDataDir();
    await loadAdmin();
    await loadKeys();
    console.log(`Key Panel Server Running on port ${PORT}`);
});