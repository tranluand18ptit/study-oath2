import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { isPlatformBrowser } from '@angular/common';
import { Injector, PLATFORM_ID, computed, inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { OAuthEvent, OAuthService } from 'angular-oauth2-oidc';
import { buildAuthConfig, RESOURCE_SERVER_ORIGIN } from './oauth.config';

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

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly injector = inject(Injector);
  private readonly platformId = inject(PLATFORM_ID);

  private configured = false;
  private pendingInitialization: Promise<boolean> | null = null;
  private oauthService: OAuthService | null = null;

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
    if (this.isBrowser()) {
      const oauthService = this.getOAuthService();
      this.configure(oauthService);
      oauthService.events.subscribe((event) => this.handleOauthEvent(event));
    } else {
      this.phase.set('anonymous');
    }
  }

  async initializeAuth(): Promise<boolean> {
    if (!this.isBrowser()) {
      this.phase.set('anonymous');
      return false;
    }

    const oauthService = this.getOAuthService();
    this.configure(oauthService);

    if (this.pendingInitialization) {
      return this.pendingInitialization;
    }

    const hasCodeInUrl = window.location.search.includes('code=');

    if (!hasCodeInUrl) {
      this.syncState();
      return this.isAuthenticated();
    }

    this.phase.set('checking');
    this.authError.set(null);

    this.pendingInitialization = oauthService
      .tryLoginCodeFlow()
      .then(() => {
        this.syncState();
        return this.isAuthenticated();
      })
      .catch((error: unknown) => {
        this.authError.set(this.describeError(error, 'Authorization code exchange failed.'));
        this.syncState();
        return false;
      })
      .finally(() => {
        this.pendingInitialization = null;
      });

    return this.pendingInitialization;
  }

  login(returnUrl = '/home'): void {
    const oauthService = this.getOAuthService();
    this.configure(oauthService);
    this.authError.set(null);
    oauthService.initCodeFlow(returnUrl);
  }

  logout(): void {
    this.getOAuthService().logOut(true);
    this.profile.set(null);
    this.profileError.set(null);
    this.authError.set(null);
    this.syncState();
  }

  async refreshAccessToken(): Promise<boolean> {
    if (!this.refreshToken()) {
      return false;
    }

    this.authError.set(null);

    try {
      await this.getOAuthService().refreshToken();
      this.syncState();
      return true;
    } catch (error: unknown) {
      this.authError.set(this.describeError(error, 'Refreshing the access token failed.'));
      this.syncState();
      return false;
    }
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
    const rawState = this.redirectState();

    if (!rawState) {
      return '/home';
    }

    try {
      const decoded = decodeURIComponent(rawState);
      return decoded.startsWith('/') ? decoded : '/home';
    } catch {
      return '/home';
    }
  }

  private configure(oauthService: OAuthService): void {
    if (this.configured || !this.isBrowser()) {
      return;
    }

    oauthService.configure(buildAuthConfig(`${window.location.origin}/callback`));
    oauthService.setStorage(localStorage);
    oauthService.setupAutomaticSilentRefresh({}, 'access_token');

    this.configured = true;
    this.syncState();
  }

  private handleOauthEvent(event: OAuthEvent): void {
    if (event.type === 'logout') {
      this.profile.set(null);
      this.profileError.set(null);
    }

    if (
      event.type === 'token_received' ||
      event.type === 'token_refreshed' ||
      event.type === 'logout'
    ) {
      this.syncState();
    }
  }

  private syncState(): void {
    if (!this.isBrowser()) {
      this.accessToken.set('');
      this.refreshToken.set('');
      this.expiresAt.set(null);
      this.grantedScope.set('');
      this.redirectState.set('/home');
      this.phase.set('anonymous');
      return;
    }

    const oauthService = this.getOAuthService();
    const nextAccessToken = oauthService.getAccessToken() ?? '';
    const nextRefreshToken = oauthService.getRefreshToken() ?? '';
    const scopes = oauthService.getGrantedScopes();

    this.accessToken.set(nextAccessToken);
    this.refreshToken.set(nextRefreshToken);
    this.expiresAt.set(nextAccessToken ? oauthService.getAccessTokenExpiration() : null);
    this.grantedScope.set(Array.isArray(scopes) ? scopes.join(' ') : 'openid profile');
    this.redirectState.set(oauthService.state || '/home');
    this.phase.set(oauthService.hasValidAccessToken() ? 'authenticated' : 'anonymous');

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

  private isBrowser(): boolean {
    return isPlatformBrowser(this.platformId);
  }

  private getOAuthService(): OAuthService {
    if (!this.oauthService) {
      this.oauthService = this.injector.get(OAuthService);
    }

    return this.oauthService;
  }
}
