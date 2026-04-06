import { AuthConfig } from 'angular-oauth2-oidc';

export const AUTH_SERVER_ORIGIN = 'http://localhost:4000';
export const RESOURCE_SERVER_ORIGIN = 'http://localhost:5000';
export const CLIENT_ID = 'oauth-study-client';

export function buildAuthConfig(redirectUri: string): AuthConfig {
  return {
    issuer: AUTH_SERVER_ORIGIN,
    loginUrl: `${AUTH_SERVER_ORIGIN}/authorize`,
    tokenEndpoint: `${AUTH_SERVER_ORIGIN}/token`,
    redirectUri,
    clientId: CLIENT_ID,
    responseType: 'code',
    scope: 'openid profile',
    oidc: false,
    requestAccessToken: true,
    requireHttps: false,
    showDebugInformation: false,
    clearHashAfterLogin: false,
    disablePKCE: false,
    timeoutFactor: 0.75,
  };
}
