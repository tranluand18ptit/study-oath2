import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { fetchProfile, decodeJwtPayload } from '../utils/auth';

export default function Home() {
  const { accessToken, logout } = useAuth();
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    async function loadProfile() {
      try {
        // ── Step 10: Fetch protected resource with Bearer JWT ─
        console.log('📦 Fetching profile from Resource Server...');
        const data = await fetchProfile(accessToken);
        setProfile(data);
        console.log('✅ Profile received:', data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    if (accessToken) loadProfile();
  }, [accessToken]);

  function handleLogout() {
    logout();
    navigate('/login', { replace: true });
  }

  const decodedToken = accessToken ? decodeJwtPayload(accessToken) : null;

  if (loading) {
    return (
      <div style={styles.container}>
        <p style={{ color: '#94a3b8' }}>Loading profile...</p>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.page}>
        <header style={styles.header}>
          <h1 style={styles.headerTitle}>🏠 Home (Protected)</h1>
          <button onClick={handleLogout} style={styles.logoutBtn}>Logout</button>
        </header>

        {error && (
          <div style={styles.error}>
            <p>❌ {error}</p>
            <button onClick={handleLogout} style={styles.retryBtn}>Re-authenticate</button>
          </div>
        )}

        {profile && (
          <div style={styles.section}>
            <h2 style={styles.sectionTitle}>📦 Resource Server Response</h2>
            <p style={styles.sectionHint}>GET /api/profile — verified via JWT</p>
            <pre style={styles.json}>{JSON.stringify(profile, null, 2)}</pre>
          </div>
        )}

        {decodedToken && (
          <div style={styles.section}>
            <h2 style={styles.sectionTitle}>🔍 Decoded JWT Payload</h2>
            <p style={styles.sectionHint}>Client-side decode (no verification — for display only)</p>
            <pre style={styles.json}>{JSON.stringify(decodedToken, null, 2)}</pre>
          </div>
        )}

        {accessToken && (
          <div style={styles.section}>
            <h2 style={styles.sectionTitle}>🎟️ Raw Access Token</h2>
            <p style={styles.sectionHint}>Copy this to jwt.io to inspect header/payload/signature</p>
            <textarea
              readOnly
              value={accessToken}
              style={styles.tokenArea}
              rows={4}
              onClick={(e) => e.target.select()}
            />
          </div>
        )}

        <div style={styles.section}>
          <h2 style={styles.sectionTitle}>📖 OAuth 2.0 + PKCE Flow Summary</h2>
          <div style={styles.flowSteps}>
            <Step n={1} done text="User visits /home → not authenticated → redirect to /login" />
            <Step n={2} done text="Click Login → generate code_verifier + code_challenge (PKCE)" />
            <Step n={3} done text="Redirect to Auth Server /authorize with code_challenge + state" />
            <Step n={4} done text="Auth Server validates client, shows login form" />
            <Step n={5} done text="User submits credentials → Auth Server issues authorization code" />
            <Step n={6} done text="Redirect back to /callback with code + state" />
            <Step n={7} done text="Client verifies state, exchanges code + code_verifier → /token" />
            <Step n={8} done text="Auth Server verifies PKCE, issues JWT access_token" />
            <Step n={9} done text="Client stores token, redirects to /home" />
            <Step n={10} done text="Client fetches /api/profile with Bearer JWT" />
            <Step n={11} done text="Resource Server verifies JWT via JWKS → returns data ✅" />
          </div>
        </div>
      </div>
    </div>
  );
}

function Step({ n, done, text }) {
  return (
    <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem', fontSize: '0.8rem' }}>
      <span style={{ color: done ? '#22c55e' : '#64748b', minWidth: '24px' }}>
        {done ? '✅' : '⬜'}
      </span>
      <span style={{ color: '#94a3b8' }}>
        <strong style={{ color: '#38bdf8' }}>Step {n}:</strong> {text}
      </span>
    </div>
  );
}

const styles = {
  container: {
    minHeight: '100vh',
    background: '#0f172a',
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    display: 'flex',
    justifyContent: 'center',
    padding: '2rem',
  },
  page: {
    width: '100%',
    maxWidth: '720px',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '2rem',
  },
  headerTitle: { color: '#f1f5f9', fontSize: '1.5rem' },
  logoutBtn: {
    padding: '0.5rem 1rem',
    background: '#dc2626',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: '500',
  },
  error: {
    background: '#7f1d1d',
    color: '#fca5a5',
    padding: '1rem',
    borderRadius: '8px',
    marginBottom: '1.5rem',
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
  section: {
    background: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '12px',
    padding: '1.5rem',
    marginBottom: '1.5rem',
  },
  sectionTitle: { color: '#f1f5f9', fontSize: '1rem', marginBottom: '0.25rem' },
  sectionHint: { color: '#64748b', fontSize: '0.75rem', marginBottom: '0.75rem' },
  json: {
    background: '#0f172a',
    color: '#38bdf8',
    padding: '1rem',
    borderRadius: '8px',
    fontSize: '0.8rem',
    lineHeight: '1.5',
    overflow: 'auto',
    border: '1px solid #334155',
  },
  tokenArea: {
    width: '100%',
    background: '#0f172a',
    color: '#fbbf24',
    border: '1px solid #334155',
    borderRadius: '8px',
    padding: '0.75rem',
    fontSize: '0.7rem',
    fontFamily: 'monospace',
    resize: 'vertical',
  },
  flowSteps: {
    background: '#0f172a',
    border: '1px solid #334155',
    borderRadius: '8px',
    padding: '1rem',
  },
};
