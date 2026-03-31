import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Callback from './pages/Callback';
import Home from './pages/Home';
import PrivateRoute from './components/PrivateRoute';

export default function App() {
  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/callback" element={<Callback />} />
        <Route
          path="/home"
          element={
            <PrivateRoute>
              <Home />
            </PrivateRoute>
          }
        />
        <Route path="*" element={<Navigate to="/home" replace />} />
      </Routes>
    </>
  );
}
