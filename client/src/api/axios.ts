import axios from 'axios';

// ── In-memory token store ─────────────────────────────────────────────────────

/** Read the raw access token from cookie (JS-readable, NOT HttpOnly). */
const getTokenFromCookie = (): string | null => {
  const match = document.cookie
    .split('; ')
    .find(c => c.startsWith('accessToken='));
  return match ? decodeURIComponent(match.split('=').slice(1).join('=')) : null;
};

/** Quick exp-check without signature verification (server still validates). */
const isTokenExpired = (token: string): boolean => {
  try {
    const [, b64] = token.split('.');
    const { exp } = JSON.parse(atob(b64));
    return !exp || exp * 1000 <= Date.now() + 30_000;
  } catch {
    return true;
  }
};

// Pre-populate from cookie so the very first API request after a page refresh
// already carries the Authorization header — no round-trip needed.
const cookieToken = getTokenFromCookie();
let accessToken: string | null =
  cookieToken && !isTokenExpired(cookieToken) ? cookieToken : null;

let logoutCallback: (() => void) | null = null;

export const setAccessToken = (token: string | null) => {
  accessToken = token;
};

export const setLogoutCallback = (cb: () => void) => {
  logoutCallback = cb;
};

// ── Axios instance ────────────────────────────────────────────────────────────

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : '/api',
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000, // 30 seconds — handles Render free tier cold start
});

// Attach access token to every request
api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// Auto-refresh on 401
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      try {
        const refreshBase = import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : '/api';
        const { data } = await axios.post(`${refreshBase}/auth/refresh`, {}, { withCredentials: true });
        const newToken = data.data.accessToken;
        setAccessToken(newToken);
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      } catch {
        setAccessToken(null);
        if (logoutCallback) {
          logoutCallback();
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;
