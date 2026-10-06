'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

if (process.loadEnvFile && fs.existsSync(path.join(__dirname, '.env'))) {
    process.loadEnvFile(path.join(__dirname, '.env'));
}

const SESSION_COOKIE = 'rm_session';
const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const PACKAGE_AMOUNTS = Object.freeze({
    Common: 1500,
    Brand: 3000,
    Super: 5500,
    Verification: 6000
});

function createApp(options = {}) {
    const databasePath = options.databasePath || process.env.DATABASE_PATH || path.join(__dirname, 'data', 'royal-motors.sqlite');
    if (databasePath !== ':memory:') fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    const db = options.db || new Database(databasePath);
    const fetchImpl = options.fetch || globalThis.fetch;
    const secretKey = options.paystackSecretKey || process.env.PAYSTACK_SECRET_KEY;

    db.pragma('foreign_keys = ON');
    db.pragma('journal_mode = WAL');
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            country TEXT NOT NULL,
            country_name TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            member_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            total_deposit_minor INTEGER NOT NULL DEFAULT 0,
            active_package TEXT NOT NULL DEFAULT 'No Package'
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payments (
            reference TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            amount_minor INTEGER NOT NULL,
            currency TEXT NOT NULL DEFAULT 'KES',
            phone TEXT NOT NULL,
            checkout_type TEXT NOT NULL,
            package_name TEXT,
            cashback_minor INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            verified_at TEXT
        );

        CREATE TABLE IF NOT EXISTS account_records (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            record_type TEXT NOT NULL,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS payments_user_idx ON payments(user_id, created_at);
        CREATE INDEX IF NOT EXISTS account_records_user_idx ON account_records(user_id, record_type, id);
    `);

    const app = express();
    app.disable('x-powered-by');
    app.use(helmet({ contentSecurityPolicy: false }));
    app.locals.db = db;
    app.locals.close = () => db.close();

    app.post('/api/payments/webhook', express.raw({ type: 'application/json', limit: '128kb' }), async (req, res) => {
        if (!secretKey) return res.status(503).json({ error: 'Payment verification is not configured on this server.' });
        const signature = req.get('x-paystack-signature') || '';
        const expected = crypto.createHmac('sha512', secretKey).update(req.body).digest();
        let supplied;
        try {
            supplied = Buffer.from(signature, 'hex');
        } catch {
            return res.status(401).json({ error: 'Invalid webhook signature.' });
        }
        if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
            return res.status(401).json({ error: 'Invalid webhook signature.' });
        }

        let event;
        try {
            event = JSON.parse(req.body.toString('utf8'));
        } catch {
            return res.status(400).json({ error: 'Invalid webhook payload.' });
        }
        if (event.event !== 'charge.success' || !event.data || typeof event.data.reference !== 'string') {
            return res.sendStatus(200);
        }

        try {
            await verifyAndRecordPayment(event.data.reference);
            return res.sendStatus(200);
        } catch (error) {
            console.error('Paystack webhook verification failed:', error.message);
            return res.status(error.statusCode || 502).json({ error: 'Payment verification is temporarily unavailable.' });
        }
    });

    app.use(express.json({ limit: '32kb' }));
    app.use('/api/auth', rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 20,
        standardHeaders: 'draft-8',
        legacyHeaders: false
    }));
    const paymentInitializationLimit = rateLimit({
        windowMs: 5 * 60 * 1000,
        limit: 10,
        standardHeaders: 'draft-8',
        legacyHeaders: false
    });

    app.use((req, res, next) => {
        if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
        const origin = req.get('origin');
        if (origin) {
            try {
                if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
            } catch {
                return res.status(403).json({ error: 'Invalid request origin.' });
            }
        }
        next();
    });

    const accountById = db.prepare('SELECT * FROM users WHERE id = ?');
    const accountRecords = db.prepare('SELECT record_type, data_json, created_at FROM account_records WHERE user_id = ? ORDER BY id');
    const depositsByUser = db.prepare('SELECT * FROM payments WHERE user_id = ? ORDER BY created_at');

    function accountDto(user) {
        const records = {
            depositRequests: [],
            withdrawalRequests: [],
            loanApplications: [],
            adSubmissions: []
        };
        for (const record of accountRecords.all(user.id)) {
            const item = JSON.parse(record.data_json);
            item.createdAt = record.created_at;
            if (record.record_type === 'withdrawal') records.withdrawalRequests.push(item);
            if (record.record_type === 'loan') records.loanApplications.push(item);
            if (record.record_type === 'ad') records.adSubmissions.push(item);
        }
        records.depositRequests = depositsByUser.all(user.id).map(payment => ({
            amount: payment.amount_minor / 100,
            phone: payment.phone,
            packageName: payment.package_name,
            checkoutType: payment.checkout_type,
            cashbackAmount: payment.cashback_minor / 100,
            paymentProvider: 'Paystack',
            paymentReference: payment.reference,
            status: payment.status === 'success' ? 'Payment verified' : payment.status === 'failed' ? 'Payment failed' : 'Awaiting payment verification',
            createdAt: payment.created_at
        }));
        return {
            id: user.id,
            username: user.username,
            name: user.name,
            phone: user.phone,
            country: user.country,
            countryName: user.country_name,
            email: user.email,
            memberId: user.member_id,
            createdAt: user.created_at,
            dashboard: {
                whatsappBalance: 0,
                whatsappWithdrawals: 0,
                cashbackBonus: 0,
                totalDeposit: user.total_deposit_minor / 100,
                activePackage: user.active_package
            },
            ...records
        };
    }

    function setSessionCookie(res, token) {
        const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
        res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE_SECONDS}${secure}`);
    }

    function clearSessionCookie(res) {
        const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
        res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
    }

    function authenticate(req, res, next) {
        const cookies = Object.fromEntries((req.get('cookie') || '').split(';').map(part => {
            const separator = part.indexOf('=');
            return separator < 0 ? ['', ''] : [part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim())];
        }).filter(([name]) => name));
        const token = cookies[SESSION_COOKIE];
        if (!token) return res.status(401).json({ error: 'Sign in to continue.' });
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const session = db.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?').get(tokenHash, Date.now());
        if (!session) {
            clearSessionCookie(res);
            return res.status(401).json({ error: 'Your session has expired. Please sign in again.' });
        }
        req.user = accountById.get(session.user_id);
        if (!req.user) return res.status(401).json({ error: 'Account not found. Please sign in again.' });
        next();
    }

    function issueSession(user, res) {
        db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
        const token = crypto.randomBytes(32).toString('base64url');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(tokenHash, user.id, Date.now() + SESSION_MAX_AGE_SECONDS * 1000);
        setSessionCookie(res, token);
    }

    function providerRequest(url, options) {
        if (!secretKey) {
            const error = new Error('Payment provider is not configured.');
            error.statusCode = 503;
            throw error;
        }
        return fetchImpl(url, {
            ...options,
            signal: AbortSignal.timeout(15000),
            headers: {
                Authorization: `Bearer ${secretKey}`,
                'Content-Type': 'application/json',
                ...(options && options.headers)
            }
        });
    }

    async function verifyAndRecordPayment(reference, userId) {
        const payment = db.prepare('SELECT * FROM payments WHERE reference = ?').get(reference);
        if (!payment || (userId && payment.user_id !== userId)) {
            const error = new Error('Payment reference not found for this account.');
            error.statusCode = 404;
            throw error;
        }
        if (payment.status === 'success') return payment;

        let response;
        try {
            response = await providerRequest(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, { method: 'GET' });
        } catch (error) {
            if (error.statusCode) throw error;
            const unavailable = new Error('Could not contact Paystack to verify this payment.');
            unavailable.statusCode = 502;
            throw unavailable;
        }
        const payload = await response.json().catch(() => null);
        if (!response.ok || !payload || payload.status !== true || !payload.data) {
            const unavailable = new Error('Paystack could not verify this payment yet.');
            unavailable.statusCode = 502;
            throw unavailable;
        }

        const transaction = payload.data;
        const user = accountById.get(payment.user_id);
        if (transaction.status !== 'success') {
            if (transaction.status === 'failed' || transaction.status === 'abandoned') {
                db.prepare("UPDATE payments SET status = 'failed' WHERE reference = ? AND status = 'pending'").run(reference);
                return { ...payment, status: 'failed' };
            }
            return { ...payment, status: 'pending' };
        }
        if (transaction.reference !== payment.reference ||
            Number(transaction.amount) !== payment.amount_minor ||
            transaction.currency !== payment.currency ||
            !transaction.customer || String(transaction.customer.email).toLowerCase() !== user.email.toLowerCase()) {
            const mismatch = new Error('The Paystack transaction does not match this payment request.');
            mismatch.statusCode = 400;
            throw mismatch;
        }

        const verifiedAt = new Date().toISOString();
        const recordVerified = db.transaction(() => {
            const latest = db.prepare('SELECT status FROM payments WHERE reference = ?').get(reference);
            if (latest.status === 'success') return;
            db.prepare("UPDATE payments SET status = 'success', verified_at = ? WHERE reference = ? AND status = 'pending'").run(verifiedAt, reference);
            const changed = db.prepare('SELECT changes() AS count').get().count;
            if (changed !== 1) return;
            db.prepare('UPDATE users SET total_deposit_minor = total_deposit_minor + ? WHERE id = ?').run(payment.amount_minor, payment.user_id);
            if (payment.package_name && payment.package_name !== 'Verification') {
                db.prepare('UPDATE users SET active_package = ? WHERE id = ?').run(`${payment.package_name} Package`, payment.user_id);
            }
        });
        recordVerified();
        return db.prepare('SELECT * FROM payments WHERE reference = ?').get(reference);
    }

    app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

    app.post('/api/auth/register', (req, res) => {
        const body = req.body || {};
        const username = String(body.username || '').trim();
        const email = String(body.email || '').trim().toLowerCase();
        const password = typeof body.password === 'string' ? body.password : '';
        const phone = String(body.phone || '').trim();
        const country = String(body.country || '').trim();
        const countryName = String(body.countryName || '').trim();
        if (body.terms !== true || !/^[A-Za-z0-9_.]{3,30}$/.test(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            password.length < 8 || password.length > 256 || phone.length < 5 || phone.length > 40 || !country || !countryName) {
            return res.status(400).json({ error: 'Accept the terms and enter a valid username, email, phone, country, and password of at least 8 characters.' });
        }
        const salt = crypto.randomBytes(16);
        const passwordHash = crypto.scryptSync(password, salt, 64);
        const createdAt = new Date().toISOString();
        try {
            const result = db.prepare(`
                INSERT INTO users (username, email, name, phone, country, country_name, password_salt, password_hash, member_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(username, email, username, phone, country, countryName, salt.toString('hex'), passwordHash.toString('hex'), `RM-${crypto.randomUUID().slice(0, 8).toUpperCase()}`, createdAt);
            const user = accountById.get(result.lastInsertRowid);
            issueSession(user, res);
            return res.status(201).json({ account: accountDto(user) });
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That email or username is already registered.' });
            console.error('Account registration failed:', error.message);
            return res.status(500).json({ error: 'Could not create the account.' });
        }
    });

    app.post('/api/auth/login', (req, res) => {
        const email = String(req.body && req.body.email || '').trim().toLowerCase();
        const password = typeof (req.body && req.body.password) === 'string' ? req.body.password : '';
        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!user || !password || password.length > 256) return res.status(401).json({ error: 'Email or password is incorrect.' });
        const salt = Buffer.from(user.password_salt, 'hex');
        const expected = Buffer.from(user.password_hash, 'hex');
        const supplied = crypto.scryptSync(password, salt, expected.length);
        if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
            return res.status(401).json({ error: 'Email or password is incorrect.' });
        }
        issueSession(user, res);
        return res.json({ account: accountDto(user) });
    });

    app.post('/api/auth/logout', authenticate, (req, res) => {
        const token = (req.get('cookie') || '').split(';').map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`));
        if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(crypto.createHash('sha256').update(decodeURIComponent(token.slice(SESSION_COOKIE.length + 1))).digest('hex'));
        clearSessionCookie(res);
        res.sendStatus(204);
    });

    app.get('/api/auth/me', authenticate, (req, res) => res.json({ account: accountDto(req.user) }));
    app.get('/api/account', authenticate, (req, res) => res.json({ account: accountDto(req.user) }));

    app.post('/api/payments/initialize', paymentInitializationLimit, authenticate, async (req, res) => {
        const body = req.body || {};
        const phone = String(body.phone || '').trim();
        const checkoutType = body.checkoutType === 'package' || body.checkoutType === 'verification' ? body.checkoutType : 'deposit';
        const packageName = checkoutType === 'verification' ? 'Verification' : checkoutType === 'package' ? String(body.packageName || '') : null;
        let amount = Number(body.amount);
        let cashback = 0;
        if (checkoutType === 'package' || checkoutType === 'verification') {
            if (!packageName || !Object.prototype.hasOwnProperty.call(PACKAGE_AMOUNTS, packageName) ||
                (checkoutType === 'verification') !== (packageName === 'Verification')) {
                return res.status(400).json({ error: 'Select a valid package.' });
            }
            amount = PACKAGE_AMOUNTS[packageName];
            cashback = packageName === 'Verification' ? 13000 : amount * 2;
        } else if (!Number.isSafeInteger(amount) || amount < 1 || amount > 10000000) {
            return res.status(400).json({ error: 'Deposit amount must be between Ksh 1 and Ksh 10,000,000.' });
        }
        if (!/^[+0-9() .-]{5,40}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid mobile money phone number.' });
        if (!secretKey) return res.status(503).json({ error: 'Paystack is not configured. Set PAYSTACK_SECRET_KEY on the server.' });

        const amountMinor = amount * 100;
        const reference = `RM-${crypto.randomUUID()}`;
        const createdAt = new Date().toISOString();
        db.prepare(`
            INSERT INTO payments (reference, user_id, amount_minor, phone, checkout_type, package_name, cashback_minor, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        `).run(reference, req.user.id, amountMinor, phone, checkoutType, packageName, cashback * 100, createdAt);

        const appUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
        try {
            const response = await providerRequest('https://api.paystack.co/transaction/initialize', {
                method: 'POST',
                body: JSON.stringify({
                    email: req.user.email,
                    amount: String(amountMinor),
                    currency: 'KES',
                    reference,
                    callback_url: `${appUrl.replace(/\/$/, '')}/?payment=paystack`,
                    channels: ['mobile_money'],
                    metadata: {
                        user_id: req.user.id,
                        phone,
                        checkout_type: checkoutType,
                        package_name: packageName
                    }
                })
            });
            const payload = await response.json().catch(() => null);
            if (!response.ok || !payload || payload.status !== true || !payload.data || !payload.data.authorization_url) {
                db.prepare("UPDATE payments SET status = 'failed' WHERE reference = ? AND status = 'pending'").run(reference);
                console.error('Paystack initialize returned an unsuccessful response.');
                return res.status(502).json({ error: 'Paystack could not start checkout. Please try again.' });
            }
            return res.status(201).json({ authorizationUrl: payload.data.authorization_url, reference });
        } catch (error) {
            db.prepare("UPDATE payments SET status = 'failed' WHERE reference = ? AND status = 'pending'").run(reference);
            if (error.statusCode === 503) return res.status(503).json({ error: error.message });
            console.error('Paystack initialization failed:', error.message);
            return res.status(502).json({ error: 'Could not connect to Paystack. Please try again.' });
        }
    });

    app.post('/api/payments/verify', authenticate, async (req, res) => {
        const reference = String(req.body && req.body.reference || '');
        if (!reference || reference.length > 100) return res.status(400).json({ error: 'A valid payment reference is required.' });
        try {
            const payment = await verifyAndRecordPayment(reference, req.user.id);
            const user = accountById.get(req.user.id);
            return res.json({
                status: payment.status,
                reference: payment.reference,
                amount: payment.amount_minor / 100,
                totalDeposit: user.total_deposit_minor / 100,
                account: accountDto(user)
            });
        } catch (error) {
            return res.status(error.statusCode || 502).json({ error: error.message });
        }
    });

    app.post('/api/withdrawals', authenticate, (req, res) => {
        const amount = Number(req.body && req.body.amount);
        const phone = String(req.body && req.body.phone || '').trim();
        if (!Number.isSafeInteger(amount) || amount < 1 || !/^[+0-9() .-]{5,40}$/.test(phone)) {
            return res.status(400).json({ error: 'Enter a valid withdrawal amount and mobile number.' });
        }
        const reserved = db.prepare("SELECT COALESCE(SUM(CAST(json_extract(data_json, '$.amount') AS INTEGER)), 0) AS total FROM account_records WHERE user_id = ? AND record_type = 'withdrawal'").get(req.user.id).total;
        const available = 0;
        if (amount > Math.max(0, available - reserved)) return res.status(400).json({ error: 'The requested amount exceeds your available balance.' });
        const createdAt = new Date().toISOString();
        db.prepare('INSERT INTO account_records (user_id, record_type, data_json, created_at) VALUES (?, ?, ?, ?)').run(req.user.id, 'withdrawal', JSON.stringify({ amount, phone, status: 'Pending review' }), createdAt);
        return res.status(201).json({ status: 'Pending review' });
    });

    app.post('/api/loan-applications', authenticate, (req, res) => {
        const body = req.body || {};
        const record = {
            fullName: String(body.fullName || '').trim(),
            email: String(body.email || '').trim().toLowerCase(),
            phone: String(body.phone || '').trim(),
            amount: Number(body.amount),
            termMonths: Number(body.termMonths),
            monthlyIncome: Number(body.monthlyIncome),
            employmentType: String(body.employmentType || ''),
            purpose: String(body.purpose || '').trim(),
            interestRate: 'Provided in lender offer after review',
            status: 'Saved locally - not submitted to lender'
        };
        if (!record.fullName || record.email !== req.user.email.toLowerCase() || !record.phone ||
            !Number.isSafeInteger(record.amount) || record.amount < 1000 ||
            ![6, 12, 24, 36, 48].includes(record.termMonths) ||
            !Number.isSafeInteger(record.monthlyIncome) || record.monthlyIncome < 1 ||
            !['Salaried', 'Self-employed', 'Business owner', 'Other'].includes(record.employmentType) ||
            record.purpose.length < 5 || record.purpose.length > 240) {
            return res.status(400).json({ error: 'Enter valid details for the loan application.' });
        }
        const createdAt = new Date().toISOString();
        db.prepare('INSERT INTO account_records (user_id, record_type, data_json, created_at) VALUES (?, ?, ?, ?)').run(req.user.id, 'loan', JSON.stringify(record), createdAt);
        return res.status(201).json({ status: record.status });
    });

    app.post('/api/ad-submissions', authenticate, (req, res) => {
        const body = req.body || {};
        const fileName = String(body.fileName || '').trim();
        const mediaType = String(body.mediaType || '');
        const requestedViews = Number(body.requestedViews);
        const durationDays = Number(body.durationDays);
        if (!fileName || fileName.length > 255 || !/^(image|video)\//.test(mediaType) ||
            !Number.isSafeInteger(requestedViews) || requestedViews < 1 ||
            !Number.isSafeInteger(durationDays) || durationDays < 1 || durationDays > 90) {
            return res.status(400).json({ error: 'Enter valid ad campaign details.' });
        }
        const createdAt = new Date().toISOString();
        db.prepare('INSERT INTO account_records (user_id, record_type, data_json, created_at) VALUES (?, ?, ?, ?)').run(req.user.id, 'ad', JSON.stringify({ fileName, mediaType, requestedViews, durationDays, status: 'Demo submission' }), createdAt);
        return res.status(201).json({ status: 'Demo submission' });
    });

    app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
    app.get('/image.jpg', (req, res) => res.sendFile(path.join(__dirname, 'image.jpg')));
    app.use((error, req, res, next) => {
        console.error('Unhandled request error:', error.message);
        res.status(error.statusCode || error.status || 500).json({
            error: error.status && error.status < 500 ? 'Invalid request.' : 'An unexpected server error occurred.'
        });
    });

    return app;
}

if (require.main === module) {
    const app = createApp();
    const port = Number(process.env.PORT) || 3000;
    app.listen(port, () => console.log(`Royal Motors server listening on port ${port}`));
}

module.exports = { createApp };
