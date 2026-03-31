import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { generateCodeVerifier, generateCodeChallenge, generateState } from '../utils/pkce';
import { config } from '../utils/auth';

export default function Login() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  // If already logged in, go to home
  if (isAuthenticated) {
    navigate('/home', { replace: true });
    return null;
  }

  async function handleLogin() {
    // ── Step 2: Generate PKCE values ──────────────────────────
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateState();

    // Store for later verification in /callback
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    sessionStorage.setItem('oauth_state', state);

    console.log('🔐 PKCE Flow Started');
    console.log('   code_verifier:', codeVerifier);
    console.log('   code_challenge:', codeChallenge);
    console.log('   state:', state);

    // ── Step 3: Redirect to Auth Server /authorize ────────────
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: config.CLIENT_ID,
      redirect_uri: config.REDIRECT_URI,
      scope: 'openid profile',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });

    window.location.href = `${config.AUTH_SERVER}/authorize?${params}`;
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>🔒 OAuth 2.0 + PKCE</h1>
        <p style={styles.subtitle}>Study App</p>

        <div style={styles.flowBox}>
          <h3 style={styles.flowTitle}>How it works:</h3>
          <ol style={styles.flowList}>
            <li><strong>Click Login</strong> → generates PKCE code_verifier + code_challenge</li>
            <li><strong>Redirect</strong> to Auth Server with code_challenge</li>
            <li><strong>Sign in</strong> on Auth Server → get authorization code</li>
            <li><strong>Callback</strong> → exchange code + code_verifier for JWT</li>
            <li><strong>Access</strong> protected resources with Bearer token</li>
          </ol>
        </div>

        <button onClick={handleLogin} style={styles.button}>
          Login with OAuth 2.0
        </button>

        <p style={styles.hint}>
          Opens Auth Server login form at localhost:4000
        </p>
      </div>
    </div>
  );
}

const styles = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    background: '#0f172a',
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  },
  card: {
    background: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '12px',
    padding: '2.5rem',
    width: '100%',
    maxWidth: '480px',
    boxShadow: '0 25px 50px rgba(0,0,0,0.5)',
  },
  title: {
    color: '#f1f5f9',
    fontSize: '1.75rem',
    textAlign: 'center',
    marginBottom: '0.25rem',
  },
  subtitle: {
    color: '#94a3b8',
    textAlign: 'center',
    fontSize: '1rem',
    marginBottom: '1.5rem',
  },
  flowBox: {
    background: '#0f172a',
    border: '1px solid #334155',
    borderRadius: '8px',
    padding: '1rem 1.25rem',
    marginBottom: '1.5rem',
  },
  flowTitle: {
    color: '#38bdf8',
    fontSize: '0.9rem',
    marginBottom: '0.5rem',
  },
  flowList: {
    color: '#cbd5e1',
    fontSize: '0.8rem',
    lineHeight: '1.8',
    paddingLeft: '1.25rem',
    margin: 0,
  },
  button: {
    width: '100%',
    padding: '0.75rem',
    background: '#3b82f6',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    fontSize: '1rem',
    fontWeight: '600',
    cursor: 'pointer',
    marginBottom: '0.75rem',
  },
  hint: {
    textAlign: 'center',
    color: '#64748b',
    fontSize: '0.75rem',
  },
};
