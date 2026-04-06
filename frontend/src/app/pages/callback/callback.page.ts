import { Component, OnInit, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../core/auth.service';

@Component({
  selector: 'app-callback-page',
  templateUrl: './callback.page.html',
  styleUrl: './callback.page.scss',
})
export class CallbackPageComponent implements OnInit {
  private readonly router = inject(Router);
  private readonly auth = inject(AuthService);

  protected readonly status = signal('Finalizing authorization code exchange...');
  protected readonly error = signal<string | null>(null);

  async ngOnInit(): Promise<void> {
    const authenticated = await this.auth.initializeAuth();

    if (authenticated) {
      this.status.set('Access token received. Loading protected profile...');
      await this.auth.loadProfile(true);
      await this.router.navigateByUrl(this.auth.getSafeRedirectTarget());
      return;
    }

    this.error.set(this.auth.authError() ?? 'Authentication failed.');
    this.status.set(
      'The callback completed, but the client did not keep an authenticated session.',
    );
  }
}
