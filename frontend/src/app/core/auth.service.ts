import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { isPlatformBrowser } from '@angular/common';
import { PLATFORM_ID, computed, inject, Injectable, signal } from '@angular/core';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import {
  AUTHORIZE_INIT_ENDPOINT,
  AUTH_SCOPE,
  CLIENT_ID,
  LOGIN_ENDPOINT,
  REDIRECT_URI,
  RESOURCE_SERVER_ORIGIN,
  TOKEN_ENDPOINT,
} from './oauth.config';

export interface DemoProfile {
  sub: string;
  username: string;
  scope: string;
  issued_at: string;
  expires_at: string;
  issuer: string;
  message: string;
}

type AuthPhase = 'checking' | 'authenticated' | 'anonymous';

interface PendingAuthTransaction {
  state: string;
  codeVerifier: string;
  returnUrl: string;
  transactionId: string;
  csrfToken: string;
  createdAt: number;
}

interface AuthorizeInitResponse {
  transaction_id: string;
  csrf_token: string;
  expires_in: number;
}

interface LoginResponse {
  code: string;
  state: string;
  redirect_to: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

const ACCESS_TOKEN_KEY = 'oauth.access_token';
const REFRESH_TOKEN_KEY = 'oauth.refresh_token';
const EXPIRES_AT_KEY = 'oauth.expires_at';
const SCOPE_KEY = 'oauth.scope';
const RETURN_URL_KEY = 'oauth.return_url';
const PENDING_TRANSACTION_KEY = 'oauth.pending_transaction';
const AUTH_STORAGE_KEYS = [
  ACCESS_TOKEN_KEY,
  REFRESH_TOKEN_KEY,
  EXPIRES_AT_KEY,
  SCOPE_KEY,
  RETURN_URL_KEY,
  PENDING_TRANSACTION_KEY,
  'access_token',
  'refresh_token',
  'expires_at',
  'granted_scopes',
  'id_token',
  'id_token_claims_obj',
  'id_token_expires_at',
  'id_token_stored_at',
  'nonce',
  'PKCE_verifier',
  'session_state',
];

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly router = inject(Router);

  private pendingInitialization: Promise<boolean> | null = null;

  readonly phase = signal<AuthPhase>('checking');
  readonly accessToken = signal('');
  readonly refreshToken = signal('');
  readonly expiresAt = signal<number | null>(null);
  readonly grantedScope = signal('');
  readonly redirectState = signal('/home');
  readonly authError = signal<string | null>(null);
  readonly profile = signal<DemoProfile | null>(null);
  readonly profileError = signal<string | null>(null);

  readonly isAuthenticated = computed(
    () => this.phase() === 'authenticated' && this.accessToken().length > 0,
  );

  readonly username = computed(() => {
    const loadedProfile = this.profile();

    if (loadedProfile) {
      return loadedProfile.username;
    }

    const token = this.accessToken();

    if (!token) {
      return 'Guest';
    }

    try {
      const [, payload] = token.split('.');
      const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
      const decoded = JSON.parse(atob(normalized)) as { username?: string };
      return typeof decoded.username === 'string' ? decoded.username : 'Guest';
    } catch {
      return 'Guest';
    }
  });

  constructor() {
    if (!this.isBrowser()) {
      this.phase.set('anonymous');
      return;
    }

    this.syncStoredSession();
  }

  async initializeAuth(): Promise<boolean> {
    if (!this.isBrowser()) {
      this.phase.set('anonymous');
      return false;
    }

    if (this.pendingInitialization) {
      return this.pendingInitialization;
    }

    const url = new URL(window.location.href);
    const hasCodeInUrl = url.searchParams.has('code');

    if (hasCodeInUrl) {
      this.phase.set('checking');
      this.authError.set(null);

      this.pendingInitialization = this.handleAuthorizationCallback(url).finally(() => {
        this.pendingInitialization = null;
      });

      return this.pendingInitialization;
    }

    if (this.hasValidAccessToken()) {
      this.syncStoredSession();
      return this.isAuthenticated();
    }

    if (this.refreshToken()) {
      this.phase.set('checking');
      this.pendingInitialization = this.refreshAccessToken().finally(() => {
        this.pendingInitialization = null;
      });
      return this.pendingInitialization;
    }

    this.syncStoredSession();
    return false;
  }

  async login(username: string, password: string, returnUrl = '/home'): Promise<boolean> {
    if (!this.isBrowser()) {
      return false;
    }

    this.authError.set(null);
    this.phase.set('checking');

    try {
      const pkce = await this.createPkceBundle();
      const initResponse = await firstValueFrom(
        this.http.post<AuthorizeInitResponse>(AUTHORIZE_INIT_ENDPOINT, {
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          response_type: 'code',
          scope: AUTH_SCOPE,
          code_challenge: pkce.codeChallenge,
          code_challenge_method: 'S256',
          state: pkce.state,
        }),
      );

      this.writePendingTransaction({
        state: pkce.state,
        codeVerifier: pkce.codeVerifier,
        returnUrl,
        transactionId: initResponse.transaction_id,
        csrfToken: initResponse.csrf_token,
        createdAt: Date.now(),
      });

      const loginResponse = await firstValueFrom(
        this.http.post<LoginResponse>(LOGIN_ENDPOINT, {
          username,
          password,
          transaction_id: initResponse.transaction_id,
          csrf_token: initResponse.csrf_token,
        }),
      );

      window.location.assign(loginResponse.redirect_to);
      return true;
    } catch (error: unknown) {
      this.authError.set(this.describeError(error, 'Login failed.'));
      this.phase.set('anonymous');
      this.clearPendingTransaction();
      return false;
    }
  }

  logout(): void {
    this.resetAuthState({ clearCallbackQuery: true });
  }

  async refreshAccessToken(): Promise<boolean> {
    if (!this.refreshToken()) {
      this.phase.set('anonymous');
      return false;
    }

    this.authError.set(null);

    try {
      const response = await firstValueFrom(
        this.http.post<TokenResponse>(TOKEN_ENDPOINT, {
          grant_type: 'refresh_token',
          refresh_token: this.refreshToken(),
          client_id: CLIENT_ID,
        }),
      );
      this.storeTokenResponse(response);
      this.syncStoredSession();
      return true;
    } catch (error: unknown) {
      const errorMessage = this.describeError(error, 'Refreshing the access token failed.');
      this.authError.set(errorMessage);
      this.resetAuthState({ preserveAuthError: true });

      if (this.isRefreshTokenExpiredError(error, errorMessage)) {
        await this.navigateToLogin();
      }

      return false;
    }
  }

  async handleUnauthorizedResponse(returnUrl?: string): Promise<boolean> {
    const refreshed = await this.refreshAccessToken();

    if (refreshed) {
      return true;
    }

    await this.navigateToLogin(returnUrl);
    return false;
  }

  async loadProfile(force = false, hasRetried = false): Promise<DemoProfile | null> {
    if (!this.isAuthenticated()) {
      this.profile.set(null);
      return null;
    }

    if (this.profile() && !force) {
      return this.profile();
    }

    this.profileError.set(null);

    try {
      const response = await firstValueFrom(
        this.http.get<DemoProfile>(`${RESOURCE_SERVER_ORIGIN}/api/profile`),
      );
      this.profile.set(response);
      return response;
    } catch (error: unknown) {
      if (!hasRetried && this.refreshToken()) {
        const refreshed = await this.refreshAccessToken();

        if (refreshed) {
          return this.loadProfile(force, true);
        }
      }

      this.profileError.set(this.describeError(error, 'The resource server rejected the request.'));
      return null;
    }
  }

  getSafeRedirectTarget(): string {
    const rawState = this.readStorage(RETURN_URL_KEY) || this.redirectState();

    if (!rawState) {
      return '/home';
    }

    try {
      const decoded = decodeURIComponent(rawState);
      this.removeStorage(RETURN_URL_KEY);
      this.redirectState.set('/home');
      return decoded.startsWith('/') ? decoded : '/home';
    } catch {
      return '/home';
    }
  }

  private syncStoredSession(): void {
    if (!this.isBrowser()) {
      this.accessToken.set('');
      this.refreshToken.set('');
      this.expiresAt.set(null);
      this.grantedScope.set('');
      this.redirectState.set('/home');
      this.phase.set('anonymous');
      return;
    }

    const nextAccessToken = this.readStorage(ACCESS_TOKEN_KEY) || '';
    const nextRefreshToken = this.readStorage(REFRESH_TOKEN_KEY) || '';
    const scopes = this.readStorage(SCOPE_KEY) || AUTH_SCOPE;
    const expiresAt = Number(this.readStorage(EXPIRES_AT_KEY) || 0);
    const returnUrl = this.readStorage(RETURN_URL_KEY) || '/home';

    this.accessToken.set(nextAccessToken);
    this.refreshToken.set(nextRefreshToken);
    this.expiresAt.set(nextAccessToken && expiresAt ? expiresAt : null);
    this.grantedScope.set(scopes);
    this.redirectState.set(returnUrl);
    this.phase.set(this.hasValidAccessToken() ? 'authenticated' : 'anonymous');

    if (!nextAccessToken) {
      this.profile.set(null);
    }
  }

  private describeError(error: unknown, fallback: string): string {
    if (error instanceof HttpErrorResponse) {
      const serverMessage =
        typeof error.error?.message === 'string'
          ? error.error.message
          : typeof error.error?.error === 'string'
            ? error.error.error
            : '';

      return serverMessage || fallback;
    }

    if (error instanceof Error) {
      return error.message || fallback;
    }

    return fallback;
  }

  private isRefreshTokenExpiredError(error: unknown, message: string): boolean {
    if (message.toLowerCase().includes('refresh token expired')) {
      return true;
    }

    if (error instanceof HttpErrorResponse) {
      const serverError = typeof error.error?.error === 'string' ? error.error.error : '';
      const serverMessage = typeof error.error?.message === 'string' ? error.error.message : '';
      return (
        error.status === 400 &&
        serverError === 'invalid_grant' &&
        /refresh token (expired|invalid)/i.test(serverMessage)
      );
    }

    return false;
  }

  private isBrowser(): boolean {
    return isPlatformBrowser(this.platformId);
  }

  private async navigateToLogin(returnUrl?: string): Promise<void> {
    if (!this.isBrowser()) {
      return;
    }

    const nextUrl = returnUrl || `${window.location.pathname}${window.location.search}` || '/home';
    await this.router.navigate(['/login'], {
      queryParams: {
        returnUrl: nextUrl.startsWith('/') ? nextUrl : '/home',
      },
    });
  }

  private async handleAuthorizationCallback(url: URL): Promise<boolean> {
    const code = url.searchParams.get('code');
    const returnedState = url.searchParams.get('state');
    const pendingTransaction = this.readPendingTransaction();

    if (!code || !returnedState || !pendingTransaction) {
      this.authError.set('Missing authorization callback state. Start login again.');
      this.resetAuthState({ clearCallbackQuery: true, preserveAuthError: true });
      return false;
    }

    if (pendingTransaction.state !== returnedState) {
      this.authError.set('State verification failed. The login response could not be trusted.');
      this.resetAuthState({ clearCallbackQuery: true, preserveAuthError: true });
      return false;
    }

    try {
      const response = await firstValueFrom(
        this.http.post<TokenResponse>(TOKEN_ENDPOINT, {
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          code_verifier: pendingTransaction.codeVerifier,
        }),
      );

      this.storeTokenResponse(response, pendingTransaction.returnUrl);
      this.clearPendingTransaction();
      this.clearCallbackQuery();
      this.syncStoredSession();
      return true;
    } catch (error: unknown) {
      this.authError.set(this.describeError(error, 'Authorization code exchange failed.'));
      this.resetAuthState({ clearCallbackQuery: true, preserveAuthError: true });
      return false;
    }
  }

  private resetAuthState(
    options: { clearCallbackQuery?: boolean; preserveAuthError?: boolean } = {},
  ): void {
    this.pendingInitialization = null;
    this.clearStoredSession();

    if (options.clearCallbackQuery) {
      this.clearCallbackQuery();
    }

    this.accessToken.set('');
    this.refreshToken.set('');
    this.expiresAt.set(null);
    this.grantedScope.set('');
    this.redirectState.set('/home');
    this.phase.set('anonymous');
    this.profile.set(null);
    this.profileError.set(null);

    if (!options.preserveAuthError) {
      this.authError.set(null);
    }
  }

  private storeTokenResponse(response: TokenResponse, returnUrl?: string): void {
    const expiresAt = Date.now() + response.expires_in * 1000;

    this.writeStorage(ACCESS_TOKEN_KEY, response.access_token);
    this.writeStorage(EXPIRES_AT_KEY, String(expiresAt));
    this.writeStorage(SCOPE_KEY, response.scope || AUTH_SCOPE);

    if (response.refresh_token) {
      this.writeStorage(REFRESH_TOKEN_KEY, response.refresh_token);
    }

    if (returnUrl) {
      this.writeStorage(RETURN_URL_KEY, returnUrl);
    }
  }

  private clearStoredSession(): void {
    for (const key of AUTH_STORAGE_KEYS) {
      this.removeStorage(key);
    }
  }

  private hasValidAccessToken(): boolean {
    const token = this.readStorage(ACCESS_TOKEN_KEY);
    const expiresAt = Number(this.readStorage(EXPIRES_AT_KEY) || 0);

    if (!token || !expiresAt) {
      return false;
    }

    return expiresAt > Date.now() + 5000;
  }

  private async createPkceBundle(): Promise<{
    codeVerifier: string;
    codeChallenge: string;
    state: string;
  }> {
    const verifierBytes = crypto.getRandomValues(new Uint8Array(64));
    const stateBytes = crypto.getRandomValues(new Uint8Array(24));
    const codeVerifier = this.base64UrlEncode(verifierBytes);
    const state = this.base64UrlEncode(stateBytes);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));

    return {
      codeVerifier,
      codeChallenge: this.base64UrlEncode(new Uint8Array(digest)),
      state,
    };
  }

  private base64UrlEncode(bytes: Uint8Array): string {
    const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  private readPendingTransaction(): PendingAuthTransaction | null {
    const raw = this.readStorage(PENDING_TRANSACTION_KEY);

    if (!raw) {
      return null;
    }

    try {
      return JSON.parse(raw) as PendingAuthTransaction;
    } catch {
      this.removeStorage(PENDING_TRANSACTION_KEY);
      return null;
    }
  }

  private writePendingTransaction(transaction: PendingAuthTransaction): void {
    this.writeStorage(PENDING_TRANSACTION_KEY, JSON.stringify(transaction));
  }

  private clearPendingTransaction(): void {
    this.removeStorage(PENDING_TRANSACTION_KEY);
  }

  private clearCallbackQuery(): void {
    if (!this.isBrowser()) {
      return;
    }

    const cleanUrl = `${window.location.origin}${window.location.pathname}`;
    window.history.replaceState({}, document.title, cleanUrl);
  }

  private writeStorage(key: string, value: string): void {
    if (!this.isBrowser()) {
      return;
    }

    window.localStorage.setItem(key, value);
  }

  private readStorage(key: string): string | null {
    if (!this.isBrowser()) {
      return null;
    }

    return window.localStorage.getItem(key);
  }

  private removeStorage(key: string): void {
    if (!this.isBrowser()) {
      return;
    }

    window.localStorage.removeItem(key);
    window.sessionStorage.removeItem(key);
  }
}
