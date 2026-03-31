import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { exchangeCodeForTokens } from '../utils/auth';

export default function Callback() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState('Exchanging authorization code for tokens...');
  const [error, setError] = useState(null);
  const [debugInfo, setDebugInfo] = useState(null);
  const { login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    async function handleCallback() {
      const code = searchParams.get('code');
      const state = searchParams.get('state');
      const errorParam = searchParams.get('error');

      // ── Error from Auth Server ──────────────────────────────
      if (errorParam) {
        setError(`Auth Server error: ${errorParam}`);
        return;
      }

      if (!code || !state) {
        setError('Missing code or state in callback URL');
        return;
      }

      // ── Step 6: Verify state (CSRF protection) ─────────────
      const savedState = sessionStorage.getItem('oauth_state');
      if (state !== savedState) {
        setError('State mismatch — possible CSRF attack!');
        return;
      }

      const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
      if (!codeVerifier) {
        setError('Missing code_verifier — PKCE flow broken');
        return;
      }

      setDebugInfo({
        authorization_code: code.substring(0, 16) + '...',
        state_match: '✅ Verified',
        code_verifier: codeVerifier.substring(0, 16) + '...',
      });

      console.log('🔄 Exchanging code for tokens...');
      console.log('   code:', code.substring(0, 16) + '...');
      console.log('   code_verifier:', codeVerifier.substring(0, 16) + '...');

      try {
        // ── Step 7: Exchange code + code_verifier for tokens ──
        const tokens = await exchangeCodeForTokens(code, codeVerifier);

        console.log('🎟️  Tokens received!');
        console.log('   access_token:', tokens.access_token.substring(0, 30) + '...');
        console.log('   token_type:', tokens.token_type);
        console.log('   expires_in:', tokens.expires_in);

        // ── Step 8: Store tokens and redirect to /home ────────
        login(tokens);
        setStatus('Success! Redirecting to home...');

        // Clean up PKCE values
        sessionStorage.removeItem('pkce_code_verifier');
        sessionStorage.removeItem('oauth_state');

        setTimeout(() => navigate('/home', { replace: true }), 1500);
      } catch (err) {
        setError(`Token exchange failed: ${err.message}`);
      }
    }

    handleCallback();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h2 style={styles.title}>🔄 OAuth Callback</h2>

        {error ? (
          <div style={styles.error}>
            <p>❌ {error}</p>
            <button onClick={() => navigate('/login')} style={styles.retryBtn}>
              Back to Login
            </button>
          </div>
        ) : (
          <>
            <p style={styles.status}>{status}</p>
            <div style={styles.spinner} />
          </>
        )}

        {debugInfo && (
          <div style={styles.debug}>
            <h4 style={styles.debugTitle}>Debug Info (Step 6-7):</h4>
            {Object.entries(debugInfo).map(([key, val]) => (
              <div key={key} style={styles.debugRow}>
                <span style={styles.debugKey}>{key}:</span>
                <span style={styles.debugVal}>{val}</span>
              </div>
            ))}
          </div>
        )}
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
    padding: '2rem',
    width: '100%',
    maxWidth: '480px',
    textAlign: 'center',
  },
  title: { color: '#f1f5f9', marginBottom: '1rem' },
  status: { color: '#94a3b8', marginBottom: '1rem' },
  spinner: {
    width: '32px',
    height: '32px',
    border: '3px solid #334155',
    borderTop: '3px solid #3b82f6',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
    margin: '0 auto',
  },
  error: {
    background: '#7f1d1d',
    color: '#fca5a5',
    padding: '1rem',
    borderRadius: '8px',
    marginBottom: '1rem',
  },
  retryBtn: {
    marginTop: '0.75rem',
    padding: '0.5rem 1rem',
    background: '#3b82f6',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  debug: {
    background: '#0f172a',
    border: '1px solid #334155',
    borderRadius: '8px',
    padding: '1rem',
    marginTop: '1.5rem',
    textAlign: 'left',
  },
  debugTitle: { color: '#38bdf8', fontSize: '0.8rem', marginBottom: '0.5rem' },
  debugRow: { marginBottom: '0.25rem', fontSize: '0.75rem' },
  debugKey: { color: '#94a3b8', marginRight: '0.5rem' },
  debugVal: { color: '#e2e8f0', fontFamily: 'monospace' },
};
