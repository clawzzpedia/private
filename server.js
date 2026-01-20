require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const session = require('express-session');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true
}));

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'sql12814774',
    waitForConnections: true,
    connectionLimit: 10
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });
    jwt.verify(token, process.env.JWT_SECRET || 'jwt-secret', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        res.json({ id: result.insertId, message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        if (rows.length === 0) return res.status(400).json({ error: 'User not found' });
        
        const user = rows[0];
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: 'Invalid password' });
        
        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'jwt-secret');
        res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    res.json(req.user);
});

// Daftar chat (user lain + last message)
app.get('/api/chats', authenticateToken, async (req, res) => {
    try {
        const [chats] = await pool.execute(`
            SELECT DISTINCT u.id, u.username, u.email, u.avatar,
                (SELECT m.message FROM messages m 
                 WHERE (m.from_user = u.id AND m.to_user = ? OR m.from_user = ? AND m.to_user = u.id)
                 ORDER BY m.timestamp DESC LIMIT 1) as lastMessage,
                (SELECT m.timestamp FROM messages m 
                 WHERE (m.from_user = u.id AND m.to_user = ? OR m.from_user = ? AND m.to_user = u.id)
                 ORDER BY m.timestamp DESC LIMIT 1) as lastTime
            FROM users u WHERE u.id != ?
            ORDER BY lastTime DESC
        `, [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id]);
        res.json(chats);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// History pesan private
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const [messages] = await pool.execute(`
            SELECT * FROM messages 
            WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
            ORDER BY timestamp ASC
        `, [req.user.id, userId, userId, req.user.id]);
        res.json(messages);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Socket.io Auth
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error'));
    jwt.verify(token, process.env.JWT_SECRET || 'jwt-secret', (err, user) => {
        if (err) return next(new Error('Invalid token'));
        socket.user = user;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`User ${socket.user.username} (ID: ${socket.user.id}) connected`);
    
    socket.on('joinChat', (targetUserId) => {
        const room = [socket.user.id, targetUserId].sort().join('_');
        socket.join(room);
        console.log(`${socket.user.username} joined room: ${room}`);
    });
    
    socket.on('sendMessage', async (data) => {
        try {
            const [result] = await pool.execute(
                'INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)',
                [socket.user.id, data.to, data.message]
            );
            
            const room = [socket.user.id, data.to].sort().join('_');
            io.to(room).emit('message', {
                id: result.insertId,
                from: socket.user.id,
                to: data.to,
                message: data.message,
                timestamp: new Date()
            });
        } catch (err) {
            socket.emit('error', err.message);
        }
    });
    
    socket.on('disconnect', () => {
        console.log(`User ${socket.user.username} disconnected`);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
