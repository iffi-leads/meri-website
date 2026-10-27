const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// Database se connect karein (Yeh khud ba khud database.db file bana lega)
const db = new sqlite3.Database('./database.db');

// Tables banayein
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS branches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, number TEXT, city TEXT, email TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, role TEXT, branch TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        branchName TEXT, number TEXT, sender TEXT, text TEXT
    )`);
});

// --- APIs ---

app.post('/api/branches', (req, res) => {
    const { name, number, city, email } = req.body;
    db.run(`INSERT INTO branches (name, number, city, email) VALUES (?, ?, ?, ?)`, 
    [name, number, city, email], function(err) {
        if(err) return res.status(500).json({error: err.message});
        res.json({ id: this.lastID, name, number, city, email });
    });
});

app.get('/api/branches', (req, res) => {
    db.all("SELECT * FROM branches", [], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/users', (req, res) => {
    const { name, role, branch } = req.body;
    db.run(`INSERT INTO users (name, role, branch) VALUES (?, ?, ?)`, 
    [name, role, branch], function(err) {
        if(err) return res.status(500).json({error: err.message});
        res.json({ id: this.lastID, name, role, branch });
    });
});

app.get('/api/users', (req, res) => {
    db.all("SELECT * FROM users", [], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/chats', (req, res) => {
    const { branchName, number, sender, text } = req.body;
    db.run(`INSERT INTO chats (branchName, number, sender, text) VALUES (?, ?, ?, ?)`, 
    [branchName, number, sender, text], function(err) {
        if(err) return res.status(500).json({error: err.message});
        res.json({ success: true });
    });
});

app.get('/api/chats/:number', (req, res) => {
    db.all("SELECT * FROM chats WHERE number = ?", [req.params.number], (err, rows) => {
        res.json(rows);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Backend running on http://localhost:3000`);
});