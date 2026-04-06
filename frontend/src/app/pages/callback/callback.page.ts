import { Component, OnInit, inject, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth.service';

@Component({
  selector: 'app-callback-page',
  imports: [RouterLink],
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
      this.status.set('Authorization code verified. Loading protected profile...');
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
