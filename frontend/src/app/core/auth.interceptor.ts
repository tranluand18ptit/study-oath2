import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { AuthService } from './auth.service';
import { RESOURCE_SERVER_ORIGIN } from './oauth.config';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith(RESOURCE_SERVER_ORIGIN)) {
    return next(req);
  }

  const auth = inject(AuthService);
  const token = auth.accessToken();

  const authorizedRequest = token
    ? req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
      })
    : req;

  return next(authorizedRequest).pipe(
    catchError((error: unknown) => {
      if (!(error instanceof HttpErrorResponse) || error.status !== 401) {
        return throwError(() => error);
      }

      if (req.headers.has('x-auth-retry')) {
        return throwError(() => error);
      }

      const returnUrl = `${window.location.pathname}${window.location.search}`;

      return from(auth.handleUnauthorizedResponse(returnUrl)).pipe(
        switchMap((refreshed) => {
          if (!refreshed) {
            return throwError(() => error);
          }

          const refreshedToken = auth.accessToken();

          if (!refreshedToken) {
            return throwError(() => error);
          }

          return next(
            req.clone({
              setHeaders: {
                Authorization: `Bearer ${refreshedToken}`,
                'x-auth-retry': 'true',
              },
            }),
          );
        }),
      );
    }),
  );
};
