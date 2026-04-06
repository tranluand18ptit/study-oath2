import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth.service';

@Component({
  selector: 'app-login-page',
  imports: [CommonModule, RouterLink],
  templateUrl: './login.page.html',
  styleUrl: './login.page.scss',
})
export class LoginPageComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  protected readonly auth = inject(AuthService);
  protected readonly returnUrl = computed(
    () => this.route.snapshot.queryParamMap.get('returnUrl') ?? '/home',
  );

  async ngOnInit(): Promise<void> {
    const authenticated = await this.auth.initializeAuth();

    if (authenticated) {
      await this.router.navigateByUrl(this.returnUrl());
    }
  }

  protected signIn(): void {
    this.auth.login(this.returnUrl());
  }
}
