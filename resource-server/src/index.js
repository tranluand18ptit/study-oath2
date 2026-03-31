import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { authMiddleware } from './middleware/authMiddleware.js';
import profileRouter from './routes/profile.js';

const app = express();
const PORT = process.env.PORT || 5000;

// ── Middleware ───────────────────────────────────────────────
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET'],
}));
app.use(express.json());

// ── Request logging (educational) ───────────────────────────
app.use((req, res, next) => {
  console.log(`\n📨 ${req.method} ${req.url}`);
  next();
});

// ── Routes ──────────────────────────────────────────────────

// Protected routes — require valid JWT
app.use(authMiddleware, profileRouter);

// Health check (unprotected)
app.get('/health', (req, res) => res.json({ status: 'ok', server: 'resource-server' }));

// ── Start ───────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n📦 Resource Server running at http://localhost:${PORT}`);
  console.log(`   Protected endpoint: GET http://localhost:${PORT}/api/profile`);
  console.log(`   JWKS source: ${process.env.AUTH_SERVER_JWKS_URL}\n`);
});
