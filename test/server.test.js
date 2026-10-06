'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createApp } = require('../server');

test('registers members and supports authenticated login and logout', async t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'royal-motors-test-'));
    const app = createApp({ databasePath: path.join(directory, 'test.sqlite') });
    const server = app.listen(0);
    t.after(() => {
        server.close();
        app.locals.close();
        fs.rmSync(directory, { recursive: true, force: true });
    });
    await new Promise(resolve => server.once('listening', resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const member = {
        username: 'loginmember',
        email: 'login@example.com',
        password: 'correct horse battery staple',
        phone: '+254700000000',
        country: 'KE',
        countryName: 'Kenya',
        terms: true
    };
    const registration = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(member)
    });
    assert.equal(registration.status, 201);
    assert.match(registration.headers.get('set-cookie'), /HttpOnly/);

    const duplicate = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(member)
    });
    assert.equal(duplicate.status, 409);

    const login = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: member.email, password: member.password })
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const account = await fetch(`${baseUrl}/api/auth/me`, { headers: { Cookie: cookie } });
    assert.equal(account.status, 200);
    assert.equal((await account.json()).account.email, member.email);

    const logout = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST', headers: { Cookie: cookie } });
    assert.equal(logout.status, 204);
    const loggedOut = await fetch(`${baseUrl}/api/auth/me`, { headers: { Cookie: cookie } });
    assert.equal(loggedOut.status, 401);
});

test('verifies Paystack payments on the server and credits Total Deposit once', async t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'royal-motors-test-'));
    const transactions = new Map();
    const paystackSecretKey = 'unit-test-secret';
    const app = createApp({
        databasePath: path.join(directory, 'test.sqlite'),
        paystackSecretKey,
        fetch: async (url, options) => {
            assert.equal(options.headers.Authorization, `Bearer ${paystackSecretKey}`);
            if (url.endsWith('/transaction/initialize')) {
                const body = JSON.parse(options.body);
                transactions.set(body.reference, {
                    reference: body.reference,
                    status: 'success',
                    amount: Number(body.amount),
                    currency: body.currency,
                    customer: { email: body.email }
                });
                return Response.json({ status: true, data: { authorization_url: 'https://checkout.paystack.test/' + body.reference } });
            }
            const reference = decodeURIComponent(url.split('/').pop());
            return Response.json({ status: true, data: transactions.get(reference) });
        }
    });
    const server = app.listen(0);
    t.after(() => {
        server.close();
        app.locals.close();
        fs.rmSync(directory, { recursive: true, force: true });
    });
    await new Promise(resolve => server.once('listening', resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    const registration = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: 'testmember',
            email: 'test@example.com',
            password: 'correct horse battery staple',
            phone: '+254700000001',
            country: 'KE',
            countryName: 'Kenya',
            terms: true
        })
    });
    assert.equal(registration.status, 201);
    const cookie = registration.headers.get('set-cookie').split(';')[0];
    const unauthenticated = await fetch(`${baseUrl}/api/account`);
    assert.equal(unauthenticated.status, 401);

    const initialization = await fetch(`${baseUrl}/api/payments/initialize`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: 125, phone: '+254700000001', checkoutType: 'deposit' })
    });
    assert.equal(initialization.status, 201);
    const payment = await initialization.json();
    assert.match(payment.authorizationUrl, /^https:\/\/checkout\.paystack\.test\//);

    const eventBody = Buffer.from(JSON.stringify({
        event: 'charge.success',
        data: { reference: payment.reference }
    }));
    const signature = crypto.createHmac('sha512', paystackSecretKey).update(eventBody).digest('hex');
    const webhookRequest = () => fetch(`${baseUrl}/api/payments/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-paystack-signature': signature },
        body: eventBody
    });
    assert.equal((await webhookRequest()).status, 200);
    assert.equal((await webhookRequest()).status, 200);

    const verification = await fetch(`${baseUrl}/api/payments/verify`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ reference: payment.reference })
    });
    assert.equal(verification.status, 200);
    const verified = await verification.json();
    assert.equal(verified.status, 'success');
    assert.equal(verified.totalDeposit, 125);
    assert.equal(verified.account.dashboard.totalDeposit, 125);
    assert.equal(verified.account.depositRequests.length, 1);
});

test('rejects webhooks with invalid signatures', async t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'royal-motors-test-'));
    const app = createApp({
        databasePath: path.join(directory, 'test.sqlite'),
        paystackSecretKey: 'unit-test-secret',
        fetch: async () => {
            throw new Error('Provider should not be called for an invalid webhook');
        }
    });
    const server = app.listen(0);
    t.after(() => {
        server.close();
        app.locals.close();
        fs.rmSync(directory, { recursive: true, force: true });
    });
    await new Promise(resolve => server.once('listening', resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/payments/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-paystack-signature': 'bad-signature' },
        body: JSON.stringify({ event: 'charge.success', data: { reference: 'fake' } })
    });
    assert.equal(response.status, 401);
});

test('uses the server package price instead of a client-supplied price', async t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'royal-motors-test-'));
    let initializedAmount;
    const app = createApp({
        databasePath: path.join(directory, 'test.sqlite'),
        paystackSecretKey: 'unit-test-secret',
        fetch: async (url, options) => {
            initializedAmount = JSON.parse(options.body).amount;
            return Response.json({ status: true, data: { authorization_url: 'https://checkout.paystack.test/package' } });
        }
    });
    const server = app.listen(0);
    t.after(() => {
        server.close();
        app.locals.close();
        fs.rmSync(directory, { recursive: true, force: true });
    });
    await new Promise(resolve => server.once('listening', resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const registration = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: 'packageuser',
            email: 'package@example.com',
            password: 'correct horse battery staple',
            phone: '+254700000002',
            country: 'KE',
            countryName: 'Kenya',
            terms: true
        })
    });
    const cookie = registration.headers.get('set-cookie').split(';')[0];
    const initialization = await fetch(`${baseUrl}/api/payments/initialize`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: 1, phone: '+254700000002', checkoutType: 'package', packageName: 'Common' })
    });
    assert.equal(initialization.status, 201);
    assert.equal(initializedAmount, '150000');
});
