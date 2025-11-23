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
    this.errorMessage = page.locator('p.text-red-600, p.text-red-400').first();
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
    
    // Wait for navigation or error message (with longer timeout for network)
    try {
      await this.page.waitForURL(/dashboard|admin/, { timeout: 20000 });
    } catch {
      // If navigation fails, check if there's an error message
      // If no error message appears within timeout, the test will fail appropriately
      await this.errorMessage.waitFor({ timeout: 3000 }).catch(() => {
        // No error message visible - likely a network/backend issue
        throw new Error('Login failed: No redirect to dashboard and no error message displayed');
      });
    }
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
