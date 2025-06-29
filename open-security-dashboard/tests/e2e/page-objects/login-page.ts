import { Page, Locator, expect } from '@playwright/test';

export class LoginPage {
  readonly page: Page;
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly loginButton: Locator;
  readonly errorMessage: Locator;
  readonly forgotPasswordLink: Locator;

  constructor(page: Page) {
    this.page = page;
    this.emailInput = page.locator('#email');
    this.passwordInput = page.locator('#password');
    this.loginButton = page.getByRole('button', { name: /sign in/i });
    this.errorMessage = page.locator('.text-red-600, .text-red-400, [role="alert"], .bg-red-50');
    this.forgotPasswordLink = page.getByText(/forgot password/i);
  }

  async goto() {
    await this.page.goto('/auth/login');
    await this.page.waitForLoadState('networkidle');
  }

  async login(email: string, password: string) {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.loginButton.click();
    
    // Wait for navigation or error message
    await Promise.race([
      this.page.waitForURL(/dashboard|admin/, { timeout: 15000 }),
      this.errorMessage.waitFor({ timeout: 5000 })
    ]);
  }

  async isLoggedIn(): Promise<boolean> {
    try {
      // Check if we're redirected to dashboard/admin or if there's user info
      return this.page.url().includes('/dashboard') || this.page.url().includes('/admin');
    } catch {
      return false;
    }
  }

  async getErrorMessage(): Promise<string> {
    try {
      await this.errorMessage.waitFor({ timeout: 2000 });
      return await this.errorMessage.textContent() || '';
    } catch {
      return '';
    }
  }
}
