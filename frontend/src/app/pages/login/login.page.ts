import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth.service';

@Component({
  selector: 'app-login-page',
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './login.page.html',
  styleUrl: './login.page.scss',
})
export class LoginPageComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly formBuilder = inject(FormBuilder);

  protected readonly auth = inject(AuthService);
  protected readonly submitting = signal(false);
  protected readonly returnUrl = computed(
    () => this.route.snapshot.queryParamMap.get('returnUrl') ?? '/home',
  );
  protected readonly loginForm = this.formBuilder.nonNullable.group({
    username: ['alice', Validators.required],
    password: ['password123', Validators.required],
  });

  async ngOnInit(): Promise<void> {
    const authenticated = await this.auth.initializeAuth();

    if (authenticated) {
      await this.router.navigateByUrl(this.returnUrl());
    }
  }

  protected async signIn(): Promise<void> {
    if (this.loginForm.invalid) {
      this.loginForm.markAllAsTouched();
      return;
    }

    this.submitting.set(true);

    try {
      const { username, password } = this.loginForm.getRawValue();
      await this.auth.login(username, password, this.returnUrl());
    } finally {
      this.submitting.set(false);
    }
  }
}
