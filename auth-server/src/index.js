import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import authorizeRouter from './routes/authorize.js';
import tokenRouter from './routes/token.js';
import { getJWKS } from './utils/jwt.js';

const app = express();
const PORT = process.env.PORT || 4000;

// ── Middleware ───────────────────────────────────────────────
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Request logging (educational) ───────────────────────────
app.use((req, res, next) => {
  console.log(`\n📨 ${req.method} ${req.url}`);
  if (Object.keys(req.body || {}).length) {
    const safe = { ...req.body };
    if (safe.password) safe.password = '***';
    console.log('   Body:', JSON.stringify(safe));
  }
  next();
});

// ── Routes ──────────────────────────────────────────────────

// Authorization endpoints
app.use(authorizeRouter);

// Token endpoint
app.use(tokenRouter);

// JWKS endpoint — Resource Server fetches this to verify JWTs
app.get('/jwks.json', (req, res) => {
  console.log('🔑 JWKS requested');
  res.json(getJWKS());
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', server: 'auth-server' }));

// ── Start ───────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🔐 Auth Server running at http://localhost:${PORT}`);
  console.log(`   JWKS endpoint: http://localhost:${PORT}/jwks.json`);
  console.log(`   Client ID: ${process.env.CLIENT_ID}`);
  console.log(`   Redirect URI: ${process.env.REDIRECT_URI}\n`);
});
