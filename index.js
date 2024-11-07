const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();
const port = 3000;

app.use(express.json());

app.use(express.static('public'));

let xssProtection = true;
let csrfProtection = true;

let csrfToken = generateCsrfToken();

function generateCsrfToken() {
    return crypto.randomBytes(16).toString('hex');
}

function csrfProtectionMiddleware(req, res, next) {
    if (csrfProtection && req.headers['x-csrf-token'] !== csrfToken) {
        return res.status(403).json({ error: 'Zahtjev ne sadrži CSRF token' });
    }
    next();
}

app.post('/toggle-xss-protection', csrfProtectionMiddleware, (req, res) => {
    xssProtection = !xssProtection;
    res.json({ xssProtection });
});

app.post('/toggle-csrf-protection', csrfProtectionMiddleware, (req, res) => {
    csrfProtection = !csrfProtection;
    csrfToken = generateCsrfToken();
    res.json({ csrfProtection });
});

app.get('/get-csrf-token', (req, res) => {
    res.json({ csrfToken: csrfProtection ? csrfToken : null });
});

app.get('/protection-status', (req, res) => {
    res.json({ xss_protected: xssProtection, csrf_protected: csrfProtection });
});

app.get('/', (req, res) => {
    res.render('index');
})

app.get('/attack', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'attack.html'));
})

app.get('/echo', (req, res) => {
    const input = req.query.input || '';
    const safeInput = xssProtection ? escapeHtml(input) : input;

    res.send(`
        <html>
            <body>
                <h1>Vaš unos: ${safeInput}</h1>
                <a href="/">Back to Home</a>
            </body>
        </html>
    `);
});

function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (match) => {
        const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return escapeMap[match];
    });
}

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
