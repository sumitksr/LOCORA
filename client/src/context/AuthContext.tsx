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

const COOKIE_ACCESS_MAX_AGE  = 24  * 60 * 60; // 1 day
const COOKIE_SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

/** Write a JS-readable cookie (not HttpOnly). */
const setCookieClient = (name: string, value: string, maxAge: number) => {
  const secure = location.protocol === 'https:' ? '; Secure' : '';
  document.cookie =
    `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure}`;
};

/** Wipe a client-side cookie. */
const clearCookieClient = (name: string) => {
  document.cookie = `${name}=; Path=/; Max-Age=0; SameSite=Lax`;
};

/** Get a cookie value by name. */
const getCookieValue = (name: string): string | null => {
  const match = document.cookie
    .split('; ')
    .find(row => row.startsWith(`${name}=`));
  if (!match) return null;
  return decodeURIComponent(match.split('=').slice(1).join('='));
};

/** Return the raw access token only if it has NOT yet expired.
 *  We decode the payload without verifying the signature — the server still
 *  validates; we just avoid firing a network call for a clearly dead token. */
const getValidAccessToken = (): string | null => {
  const token = getCookieValue('accessToken');
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    // 60-second grace window so we don't use a token that expires mid-request
    if (payload.exp && payload.exp * 1000 > Date.now() + 60_000) {
      return token;
    }
  } catch {
    // malformed — discard
  }
  return null;
};

/** True when the isLoggedIn sentinel cookie exists (any value). */
const hasSessionCookie = () =>
  document.cookie.split('; ').some(c => c.startsWith('isLoggedIn='));

const buildBase = () =>
  import.meta.env.VITE_API_URL
    ? `${import.meta.env.VITE_API_URL}/api`
    : '/api';

// ── Provider ──────────────────────────────────────────────────────────────────

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessTokenState] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(hasSessionCookie);
  const hasChecked = useRef(false);

  // ── login: called after a successful sign-in / sign-up / refresh ────────────
  const login = (userData: User, token: string) => {
    setUser(userData);
    setAccessTokenState(token);
    setAccessToken(token);
    // Write both cookies from the client side so they survive a page refresh
    // even if the server's Set-Cookie header was dropped by the Vite proxy.
    setCookieClient('accessToken', token, COOKIE_ACCESS_MAX_AGE);
    setCookieClient('isLoggedIn', 'true', COOKIE_SESSION_MAX_AGE);
  };

  // ── clearAuth: wipe everything ──────────────────────────────────────────────
  const clearAuth = () => {
    setUser(null);
    setAccessTokenState(null);
    setAccessToken(null);
    clearCookieClient('accessToken');
    clearCookieClient('isLoggedIn');
  };

  // ── logout: tell server then wipe locally ───────────────────────────────────
  const logout = async () => {
    try { await authApi.logout(); } catch (e) {
      console.error('Logout request failed', e);
    } finally {
      clearAuth();
    }
  };

  // ── checkAuth: called once on mount when a prior session might exist ────────
  const checkAuth = async () => {
    // ── FAST PATH ─────────────────────────────────────────────────────────────
    // If a valid accessToken cookie exists, restore auth state from it
    // immediately without any network call. Then fetch the user profile in the
    // background to get up-to-date user data.
    const savedToken = getValidAccessToken();

    if (savedToken) {
      // Restore token in memory right away so API calls work before /me returns
      setAccessToken(savedToken);
      setAccessTokenState(savedToken);

      // Fetch user profile with the restored token
      try {
        const { data } = await axios.get(`${buildBase()}/auth/me`, {
          headers: { Authorization: `Bearer ${savedToken}` },
          withCredentials: true,
        });
        if (data?.success && data?.data) {
          setUser(data.data);
          // Refresh the accessToken cookie TTL
          setCookieClient('accessToken', savedToken, COOKIE_ACCESS_MAX_AGE);
          setCookieClient('isLoggedIn', 'true', COOKIE_SESSION_MAX_AGE);
          setIsLoading(false);
          return; // ✅ done — skip the slow path
        }
      } catch {
        // /me returned 401 (token expired server-side) — fall through to slow path
        // but DON'T clear auth yet; the refresh might save us
      }
    }

    // ── SLOW PATH ─────────────────────────────────────────────────────────────
    // No valid accessToken cookie, or /me rejected it.
    // Try to exchange the HttpOnly refreshToken cookie for a fresh pair.
    try {
      const { data } = await axios.post(
        `${buildBase()}/auth/refresh`,
        {},
        { withCredentials: true },
      );
      if (data?.success && data?.data) {
        login(data.data.user, data.data.accessToken);
      } else {
        clearAuth();
      }
    } catch {
      // Refresh token missing / expired → user needs to sign in again
      clearAuth();
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    setLogoutCallback(clearAuth);

    if (!hasChecked.current) {
      hasChecked.current = true;
      if (hasSessionCookie()) {
        checkAuth();
      } else {
        // No session evidence at all — stop loading immediately
        setIsLoading(false);
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
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
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};
