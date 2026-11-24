# Roulette Flow Master

A minimal, secure Node.js (v20+) wrapper serving Roulette Flow Master behind a single shared access key.

## Features
- **Zero data stored on server**: Spin history remains strictly in browser `localStorage`.
- **Timing-safe authentication**: Key verification uses `crypto.timingSafeEqual` over SHA-256 digests.
- **One-time HMAC login**: the signed login cookie is consumed when `/app` loads. Refreshes, server restarts, and other devices require the access key again.
- **Hardened security**: Helmet CSP (inline scripts/styles allowed, all external network requests blocked), rate-limited login (5 attempts/min), `Cache-Control: no-store`, `X-Robots-Tag: noindex`.
- **Render ready**: `trust proxy: 1`, `/healthz` health check endpoint.

## Local Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Set your environment variables:
- `ACCESS_KEY`: The shared secret key for access.
- `COOKIE_SECRET`: A long random secret for HMAC signing.
- `PORT`: (Optional, defaults to 3007).

### 3. Run
```bash
npm start
```
The server loads `.env` automatically for local development. In deployment, set the environment variables in the hosting provider.
Visit `http://localhost:3007`.

## Deployment (Render)

1. Connect your repository to Render as a **Web Service**.
2. **Environment**: Node
3. **Build Command**: `npm install`
4. **Start Command**: `npm start`
5. **Health Check Path**: `/healthz`
6. Add Environment Variables under **Environment**:
   - `ACCESS_KEY`: `<your-secure-password>`
   - `COOKIE_SECRET`: `<generated-random-secret>`
   - `NODE_ENV`: `production`

## Routes
- `GET /` - Login page
- `POST /api/login` - Authenticate via JSON `{ "key": "..." }`
- `GET /app` - Access protected app (redirects to `/` if unauthenticated)
- `GET /logout` or `POST /api/logout` - Clear session and log out
- `GET /healthz` - Service health check
