const express = require('express');
const cors = require('cors');
const { query } = require('./db');
const crypto = require('crypto');
const fetch = require('node-fetch'); // ensuring v2 is installed for require

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("CRITICAL ERROR: JWT_SECRET authentication key is missing in .env.");
    process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

app.use(helmet()); // Secure HTTP Headers
app.use(cors()); // TODO: Restrict this to your frontend domain in production
app.use(express.json());

// Rate Limiter for Auth Routes (Prevents Brute Force)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 requests per windowMs
    message: "Too many login attempts from this IP, please try again after 15 minutes"
});
app.use('/api/auth/', authLimiter);

// Helper: Discord Notification
async function sendDiscordNotification(clientName, proposal, title, description = "") {
    if (!DISCORD_WEBHOOK_URL || DISCORD_WEBHOOK_URL.includes("TU_DISCORD_WEBHOOK_URL_AQUI")) {
        console.warn("Discord Webhook no configurado/invalido. No se envía notificación.");
        return;
    }

    const colorMap = {
        "Propuesta Aprobada": 5763719, // Green
        "Propuesta Rechazada": 15548997, // Red
        "Modificación Solicitada": 16776960, // Yellow
        "Modificación Aplicada": 3447003 // Blue
    };

    const content = {
        username: "Elevare Admin System",
        // avatar_url: "...", // Optional
        embeds: [{
            title: `${title}: ${clientName}`,
            description: description ? `**Detalle:** ${description}` : undefined,
            color: colorMap[title] || 3447003,
            fields: [
                { name: "Rubro", value: proposal.rubro || "N/A", inline: true },
                { name: "ID Propuesta", value: `#${proposal.id || 'N/A'}`, inline: true }
            ],
            footer: { text: "Gestionado por Backend Layer" },
            timestamp: new Date().toISOString()
        }]
    };

    try {
        await fetch(DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(content)
        });
    } catch (error) {
        console.error("Error enviando a Discord:", error);
    }
}

// Middleware: Authenticate Token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Basic health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// --- AUTH ROUTER ---

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: "Email y contraseña requeridos" });

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save User
        const result = await query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
            [email, hashedPassword]
        );

        res.status(201).json({ message: "Usuario registrado", user: result.rows[0] });
    } catch (err) {
        console.error(err);
        if (err.code === '23505') { // Unique violation
            return res.status(409).json({ error: "El correo ya está registrado." });
        }
        res.status(500).json({ error: "Error al registrar usuario." });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find User
        const result = await query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: "Credenciales inválidas" });

        const user = result.rows[0];

        // Check Password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: "Credenciales inválidas" });

        // Generate Token
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

        res.json({ message: "Login exitoso", token, user: { id: user.id, email: user.email } });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error al iniciar sesión" });
    }
});

// GET /api/auth/me
app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// GET /api/proposals - List all
app.get('/api/proposals', async (req, res) => {
    try {
        const result = await query('SELECT * FROM proposals ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// GET /api/proposals/:id
app.get('/api/proposals/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const isNumeric = !isNaN(id);
        const field = isNumeric ? 'id' : 'access_token';
        const result = await query(`SELECT * FROM proposals WHERE ${field} = $1`, [id]);

        if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/proposals - Create
app.post('/api/proposals', async (req, res) => {
    try {
        const body = req.body;
        const clientName = body.nombre_empresa || body.clientName || 'Cliente';
        const accessToken = crypto.randomUUID();

        const result = await query(
            'INSERT INTO proposals (client_name, data, access_token) VALUES ($1, $2, $3) RETURNING *',
            [clientName, JSON.stringify(body), accessToken]
        );

        // Link Generation
        const link = `/view.html?token=${accessToken}`;

        res.status(201).json({ message: 'Created', proposal: result.rows[0], link });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// PUT /api/proposals/:id - Update & Consensus Logic
app.put('/api/proposals/:id', authenticateToken, async (req, res) => { // Added authenticateToken
    try {
        const { id } = req.params;
        // User info from token, trusted.
        const user_email = req.user.email;
        const uid = req.user.id; // Using DB ID as UID

        const { action, text, ...otherUpdates } = req.body;

        // 1. Fetch Current
        const currentResult = await query('SELECT * FROM proposals WHERE id = $1', [id]);
        if (currentResult.rows.length === 0) return res.status(404).json({ error: 'Not found' });

        const currentRow = currentResult.rows[0];
        let data = currentRow.data;
        let status = currentRow.status;
        const clientName = currentRow.client_name;

        // 2. Apply Custom Action Logic
        if (action) {
            if (!data.historial) data.historial = [];
            if (!data.votes) data.votes = {};
            const timestamp = new Date().toISOString();

            // --- LOGIC MIGRATION start ---

            // A. Modifications
            if (action === 'modify') {
                data.pending_modification = { reason: text, proposer: user_email, timestamp };
                data.historial.push({ action: 'propose_mod', user_email, timestamp, details: text });
                await sendDiscordNotification(clientName, { id: id, ...data }, "Modificación Solicitada", text);
            }
            else if (action === 'accept_mod') {
                const mod = data.pending_modification;
                data.historial.push({ action: 'accept_mod', user_email, timestamp, details: "Modificación aplicada." });
                if (!data.modification_notes) data.modification_notes = [];
                data.modification_notes.push(`Cambio aplicado (${new Date().toLocaleDateString()}): ${mod.reason}`);
                delete data.pending_modification;
                await sendDiscordNotification(clientName, { id: id, ...data }, "Modificación Aplicada", "Cambios integrados.");
            }
            else if (action === 'reject_mod') {
                data.historial.push({ action: 'reject_mod', user_email, timestamp, details: text });
                delete data.pending_modification;
            }

            // B. Voting (Approve/Reject)
            else if (action === 'approve' || action === 'reject') {
                const voteAction = action === 'approve' ? 'aprobado' : 'rechazado';
                data.votes[uid] = {
                    action: voteAction,
                    reason: text,
                    user_email,
                    timestamp
                };
                data.historial.push({ action, user_email, timestamp, details: text });

                // Consensus Check
                const votes = Object.values(data.votes);
                const app = votes.filter(v => v.action === 'aprobado').length;
                const rej = votes.filter(v => v.action === 'rechazado').length;

                if (app >= 2 && status !== 'aprobado') {
                    status = 'aprobado';
                    data.historial.push({ action: 'became_approved', user_email: 'SYSTEM', timestamp, details: 'Consenso (2 votos).' });
                    await sendDiscordNotification(clientName, { id: id, ...data }, "Propuesta Aprobada");
                }
                else if (rej >= 2 && status !== 'rechazado') {
                    status = 'rechazado';
                    data.historial.push({ action: 'became_rejected', user_email: 'SYSTEM', timestamp, details: 'Consenso (2 votos).' });
                    await sendDiscordNotification(clientName, { id: id, ...data }, "Propuesta Rechazada");
                }
            }
            // --- LOGIC MIGRATION end ---
        } else {
            // Normal update without special action logic (merge generic data)
            data = { ...data, ...otherUpdates };
            if (otherUpdates.estado) status = otherUpdates.estado;
        }

        // 3. Save
        const result = await query(
            'UPDATE proposals SET data = $1, status = $2, updated_at = NOW() WHERE id = $3 RETURNING *',
            [JSON.stringify(data), status, id]
        );

        res.json({ message: 'Updated', proposal: result.rows[0] });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE
app.delete('/api/proposals/:id', async (req, res) => {
    try {
        await query('DELETE FROM proposals WHERE id = $1', [req.params.id]);
        res.json({ message: 'Deleted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
