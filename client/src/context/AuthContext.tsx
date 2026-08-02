import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { authApi } from '../api/auth';
import { setAccessToken, setLogoutCallback } from '../api/axios';
import type { User } from '../types';

interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (user: User, token: string) => void;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// ── Cookie helpers ────────────────────────────────────────────────────────────

const COOKIE_ACCESS_MAX_AGE = 24 * 60 * 60;       // 1 day (matches server)
const COOKIE_SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

const getCookieValue = (name: string): string | null => {
  const match = document.cookie
    .split('; ')
    .find(c => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.split('=').slice(1).join('=')) : null;
};

const setCookie = (name: string, value: string, maxAge: number) => {
  const secure = location.protocol === 'https:' ? '; Secure' : '';
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure}`;
};

const clearCookie = (name: string) => {
  document.cookie = `${name}=; Path=/; Max-Age=0; SameSite=Lax`;
};

/** Read the access token JWT from cookie and check it hasn't expired yet.
 *  Does NOT verify the signature (that's the server's job) — just checks exp. */
const getValidAccessTokenFromCookie = (): string | null => {
  const token = getCookieValue('accessToken');
  if (!token) return null;
  try {
    const [, payloadB64] = token.split('.');
    const payload = JSON.parse(atob(payloadB64));
    // Give a 30-second buffer before expiry so we refresh slightly early
    if (payload.exp && payload.exp * 1000 > Date.now() + 30_000) {
      return token;
    }
  } catch {
    // malformed token — treat as missing
  }
  return null;
};

const hasSessionCookie = () =>
  document.cookie.split('; ').some(c => c.startsWith('isLoggedIn=true'));

const buildRefreshBase = () =>
  import.meta.env.VITE_API_URL
    ? `${import.meta.env.VITE_API_URL}/api`
    : '/api';

// ── Provider ──────────────────────────────────────────────────────────────────

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessTokenState] = useState<string | null>(null);
  // Start loading only if a session cookie is present — avoids flicker for guests
  const [isLoading, setIsLoading] = useState(() => hasSessionCookie());
  const hasChecked = useRef(false);

  const login = (userData: User, token: string) => {
    setUser(userData);
    setAccessTokenState(token);
    setAccessToken(token);
    // Persist both access token and session flag in JS-readable cookies
    setCookie('accessToken', token, COOKIE_ACCESS_MAX_AGE);
    setCookie('isLoggedIn', 'true', COOKIE_SESSION_MAX_AGE);
  };

  const clearAuth = () => {
    setUser(null);
    setAccessTokenState(null);
    setAccessToken(null);
    clearCookie('accessToken');
    clearCookie('isLoggedIn');
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch (e) {
      console.error('Logout request failed', e);
    } finally {
      clearAuth();
    }
  };

  /** Restore session from cookies.
   *  Strategy:
   *  1. If the accessToken cookie holds a still-valid JWT → restore immediately,
   *     then fire a background refresh to get a fresh token + user data.
   *  2. If the accessToken cookie is missing or expired but isLoggedIn exists →
   *     hit /auth/refresh to exchange the HttpOnly refreshToken for a new pair.
   *  3. If everything is missing or the refresh fails → clear state (guest). */
  const checkAuth = async () => {
    // Fast path: we already have a valid access token in cookie
    const cachedToken = getValidAccessTokenFromCookie();
    if (cachedToken) {
      // Restore the token into memory immediately so the app renders without waiting
      setAccessToken(cachedToken);
      setAccessTokenState(cachedToken);

      // Then fetch the user profile with this token (avoids stale user data)
      try {
        const { data } = await axios.get(`${buildRefreshBase()}/auth/me`, {
          headers: { Authorization: `Bearer ${cachedToken}` },
          withCredentials: true,
        });
        if (data?.success && data?.data) {
          setUser(data.data);
        } else {
          // Token rejected by server — do a full refresh
          await doSilentRefresh();
          return;
        }
      } catch {
        // /me failed — maybe token expired server-side, try a refresh
        await doSilentRefresh();
        return;
      } finally {
        setIsLoading(false);
      }
      return;
    }

    // Slow path: accessToken cookie missing/expired, try the HttpOnly refreshToken
    await doSilentRefresh();
  };

  const doSilentRefresh = async () => {
    try {
      // Raw axios (no interceptors) so a 401 here doesn't fire the logout
      // callback and wipe state before we've finished initialising.
      const { data } = await axios.post(
        `${buildRefreshBase()}/auth/refresh`,
        {},
        { withCredentials: true },
      );
      if (data?.success && data?.data) {
        // Server sets refreshToken + accessToken + isLoggedIn cookies via Set-Cookie.
        // We also call login() to update React state AND write the accessToken cookie
        // from JS so future page loads can skip this round-trip.
        login(data.data.user, data.data.accessToken);
      } else {
        clearAuth();
      }
    } catch {
      // No valid session — normal on first visit or after token expiry.
      clearAuth();
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    setLogoutCallback(clearAuth);

    // Only attempt restoration if there's evidence of a prior session
    if (!hasChecked.current && hasSessionCookie()) {
      hasChecked.current = true;
      checkAuth();
    } else if (!hasSessionCookie()) {
      // No session cookie — we can stop loading immediately
      setIsLoading(false);
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        checkAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
