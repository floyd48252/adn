# Royal Motors member portal

## Run locally

Requires Node.js 20.12 or newer. Install dependencies and create a private `.env` file from the example:

```sh
npm.cmd install
```

On Windows PowerShell, create the private environment file with `Copy-Item .env.example .env`. Set `PAYSTACK_SECRET_KEY` to the secret key from the Paystack account that receives the payments. Keep it only in the server environment; never put it in browser code or commit `.env`. Start the site with:

```sh
npm.cmd start
```

Open `http://localhost:3000`. The server serves the page and API on the same origin and stores accounts, sessions, and payment records in the SQLite file selected by `DATABASE_PATH`.

## Paystack payment verification

The server initializes each transaction using the signed-in account's email and a server-generated reference. The browser is redirected to Paystack and then requests server-side verification when Paystack redirects back. A transaction is credited to Total Deposit only after Paystack confirms its reference, amount, currency, and payer email. Repeated callbacks and webhooks are idempotent.

For payments to be verified even if the customer closes the browser, configure the Paystack dashboard webhook URL as:

```text
https://YOUR_PUBLIC_SITE/api/payments/webhook
```

Set `APP_URL` to the public HTTPS site URL. In production, set `NODE_ENV=production` so session cookies are Secure, and use persistent disk storage for SQLite. Back up the database. Deploy as a single server instance; SQLite on ephemeral or shared multi-instance hosting is not suitable.

Test the backend with `npm.cmd test`. The tests use a fake Paystack API and do not charge a real account.

## Existing browser demo accounts

On the same browser origin, a member can sign in with the old demo credentials and the site will move the account profile to the server. Browser-only balances and payment records are deliberately not imported: they were not verified by Paystack and must not be treated as paid funds.
