import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth.service';

@Component({
  selector: 'app-home-page',
  imports: [CommonModule, RouterLink],
  templateUrl: './home.page.html',
  styleUrl: './home.page.scss',
})
export class HomePageComponent implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly loadingProfile = signal(false);
  protected readonly refreshingToken = signal(false);
  protected readonly loggingOut = signal(false);

  protected readonly tokenPreview = computed(() => {
    const token = this.auth.accessToken();

    if (!token) {
      return 'No access token is currently stored.';
    }

    if (token.length < 60) {
      return token;
    }

    return `${token.slice(0, 42)}...${token.slice(-18)}`;
  });

  protected readonly profileJson = computed(() => {
    const profile = this.auth.profile();
    return profile ? JSON.stringify(profile, null, 2) : 'Profile not loaded yet.';
  });

  protected readonly expiresLabel = computed(() => {
    const expiresAt = this.auth.expiresAt();
    return expiresAt ? new Date(expiresAt).toLocaleString() : 'No active token';
  });

  async ngOnInit(): Promise<void> {
    await this.reloadProfile();
  }

  protected async reloadProfile(): Promise<void> {
    this.loadingProfile.set(true);
    await this.auth.loadProfile(true);
    this.loadingProfile.set(false);
  }

  protected async renewAccessToken(): Promise<void> {
    this.refreshingToken.set(true);
    const refreshed = await this.auth.refreshAccessToken();

    if (refreshed) {
      await this.reloadProfile();
    }

    this.refreshingToken.set(false);
  }

  protected async signOut(): Promise<void> {
    this.loggingOut.set(true);
    this.auth.logout();
    await this.router.navigate(['/login']);
    this.loggingOut.set(false);
  }
}
