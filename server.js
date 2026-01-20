const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

// SERVE STATIC FILES DARI ROOT
app.use(express.static(__dirname));
app.use(cors({ origin: '*' }));
app.use(express.json());

// INFINITYFREE DATABASE - HARDCODE
const pool = mysql.createPool({
    host: 'sql300.infinityfree.com',
    user: 'if0_40947237',
    password: 'clawzz3411',
    database: 'if0_40947237_chat_db',
    port: 3306,
    connectTimeout: 60000,
    acquireTimeout: 60000,
    ssl: { rejectUnauthorized: false }
});

// AUTH MIDDLEWARE
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token required' });
    jwt.verify(token, 'jwt-secret-2026-supersecret', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// REGISTER
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        res.json({ success: true, id: result.insertId, message: 'Registered!' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Email sudah digunakan' });
        } else {
            res.status(500).json({ error: err.message });
        }
    }
});

// LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(400).json({ error: 'User tidak ditemukan' });
        
        const user = rows[0];
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: 'Password salah' });
        
        const token = jwt.sign({ id: user.id, username: user.username }, 'jwt-secret-2026-supersecret');
        res.json({ token, user: { id: user.id, username: user.username } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PROFILE
app.get('/api/profile', authenticateToken, (req, res) => res.json(req.user));

// CHATS LIST
app.get('/api/chats', authenticateToken, async (req, res) => {
    const [chats] = await pool.execute('SELECT id, username FROM users WHERE id != ?', [req.user.id]);
    res.json(chats);
});

// MESSAGES
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    const [messages] = await pool.execute(
        'SELECT * FROM messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) ORDER BY timestamp',
        [req.user.id, userId, userId, req.user.id]
    );
    res.json(messages);
});

// SOCKET.IO
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    jwt.verify(token, 'jwt-secret-2026-supersecret', (err, user) => {
        if (err) return next(new Error('Invalid token'));
        socket.user = user;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`👤 ${socket.user.username} connected`);
    
    socket.on('sendMessage', async (data) => {
        const [result] = await pool.execute(
            'INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)',
            [socket.user.id, data.to, data.message]
        );
        
        io.emit('message', {
            from: socket.user.id,
            to: data.to,
            message: data.message,
            timestamp: new Date()
        });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server: http://localhost:${PORT}`);
});
