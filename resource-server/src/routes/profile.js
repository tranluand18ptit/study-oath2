import { Router } from 'express';

const router = Router();

/**
 * GET /api/profile
 *
 * Protected resource. Returns the user's profile from the JWT claims.
 * The authMiddleware has already verified the token and set req.user.
 */
router.get('/api/profile', (req, res) => {
  const { sub, username, scope, iat, exp, iss } = req.user;

  res.json({
    sub,
    username,
    scope,
    issued_at: new Date(iat * 1000).toISOString(),
    expires_at: new Date(exp * 1000).toISOString(),
    issuer: iss,
    message: `Hello ${username}! This data came from the Resource Server, verified via JWT.`,
  });
});

export default router;
