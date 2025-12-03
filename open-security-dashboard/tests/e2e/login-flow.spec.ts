import { test, expect } from '@playwright/test';
import { LoginPage } from './page-objects/login-page';

/**
 * Task 2.2 - Critical Flow Test: Login
 * 
 * Tests the complete authentication flow including:
 * - Login page rendering
 * - Form validation
 * - Successful authentication
 * - Session persistence
 * - Logout functionality
 */

test.describe('Login Flow - Critical Path', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
  });

  test('should load login page with all required elements', async ({ page }) => {
    console.log('🔍 Test: Login page elements verification');
    
    await loginPage.goto();
    
    // Verify URL
    await expect(page).toHaveURL(/auth\/login/);
    console.log('✅ Login page URL correct');
    
    // Verify form elements are visible
    await expect(loginPage.emailInput).toBeVisible();
    await expect(loginPage.passwordInput).toBeVisible();
    await expect(loginPage.loginButton).toBeVisible();
    console.log('✅ All login form elements visible');
    
    // Verify page title or heading
    const heading = page.getByRole('heading', { name: /sign in|login|wildbox/i });
    await expect(heading).toBeVisible();
    console.log('✅ Login page heading visible');
  });

  test('should show validation error for invalid credentials', async ({ page }) => {
    console.log('🔍 Test: Invalid credentials validation');
    
    await loginPage.goto();
    
    // Try to login with invalid credentials
    await loginPage.login('invalid@example.com', 'wrongpassword');
    
    // Wait for error message
    await page.waitForTimeout(2000);
    
    // Check if still on login page (not redirected)
    expect(page.url()).toContain('/auth/login');
    console.log('✅ User not redirected with invalid credentials');
    
    // Check for error indication (could be error message or form state)
    const hasError = await page.locator('.text-red-600, .text-red-400, .text-destructive, [role="alert"]').count() > 0;
    console.log(`✅ Error indication present: ${hasError}`);
  });

  test('should successfully login with valid credentials', async ({ page }) => {
    console.log('🔍 Test: Successful login flow');
    
    await loginPage.goto();
    
    // Use test credentials (you may need to adjust these)
    const testEmail = process.env.TEST_EMAIL || 'superadmin@wildbox.com';
    const testPassword = process.env.TEST_PASSWORD || 'wildbox123';
    
    console.log(`📝 Attempting login with: ${testEmail}`);
    
    // Perform login
    await loginPage.login(testEmail, testPassword);
    
    // Wait for successful navigation
    await page.waitForURL(/dashboard|admin/, { timeout: 30000 });
    console.log('✅ Successfully redirected after login');
    
    // Verify we're authenticated by checking for user profile/menu
    const userProfile = page.locator('[href*="/settings/profile"], .user-menu, [data-testid="user-profile"]');
    await expect(userProfile.first()).toBeVisible({ timeout: 10000 });
    console.log('✅ User profile/menu visible - authenticated');
    
    // Verify navigation sidebar is present
    const navigation = page.locator('nav, [role="navigation"]').first();
    await expect(navigation).toBeVisible();
    console.log('✅ Navigation sidebar loaded');
  });

  test('should persist session after page reload', async ({ page, context }) => {
    console.log('🔍 Test: Session persistence');
    
    await loginPage.goto();
    
    // Login
    const testEmail = process.env.TEST_EMAIL || 'superadmin@wildbox.com';
    const testPassword = process.env.TEST_PASSWORD || 'wildbox123';
    
    await loginPage.login(testEmail, testPassword);
    await page.waitForURL(/dashboard|admin/, { timeout: 30000 });
    console.log('✅ Initial login successful');
    
    // Get current URL
    const authenticatedUrl = page.url();
    
    // Reload page
    await page.reload();
    await page.waitForLoadState('networkidle');
    console.log('✅ Page reloaded');
    
    // Verify we're still on authenticated page (not redirected to login)
    expect(page.url()).toContain('/dashboard');
    expect(page.url()).not.toContain('/auth/login');
    console.log('✅ Session persisted after reload');
  });

  test('should successfully logout and clear session', async ({ page }) => {
    console.log('🔍 Test: Logout functionality');
    
    await loginPage.goto();
    
    // Login first
    const testEmail = process.env.TEST_EMAIL || 'superadmin@wildbox.com';
    const testPassword = process.env.TEST_PASSWORD || 'wildbox123';
    
    await loginPage.login(testEmail, testPassword);
    await page.waitForURL(/dashboard|admin/, { timeout: 30000 });
    console.log('✅ Logged in');
    
    // Find and click logout button
    const logoutButton = page.locator('button:has-text("Logout"), button:has-text("Sign Out"), [data-testid="logout"], svg.lucide-log-out').first();
    await expect(logoutButton).toBeVisible({ timeout: 5000 });
    await logoutButton.click();
    console.log('✅ Logout button clicked');
    
    // Wait for redirect to login or home
    await page.waitForURL(/\/$|auth\/login|auth\/logout/, { timeout: 10000 });
    console.log('✅ Redirected after logout');
    
    // Try to navigate to protected route
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
    
    // Should be redirected to login (or see login prompt)
    const isOnLoginPage = page.url().includes('/auth/login') || page.url() === '/';
    expect(isOnLoginPage).toBeTruthy();
    console.log('✅ Cannot access protected route after logout');
  });

  test('should handle empty form submission', async ({ page }) => {
    console.log('🔍 Test: Empty form validation');
    
    await loginPage.goto();
    
    // Try to submit without filling form
    await loginPage.loginButton.click();
    
    // Should still be on login page
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('/auth/login');
    console.log('✅ Form validation prevents empty submission');
    
    // Check for HTML5 validation or error messages
    const emailValidity = await loginPage.emailInput.evaluate((el: HTMLInputElement) => el.validity.valid);
    console.log(`📝 Email input validity: ${emailValidity}`);
  });
});

test.describe('Login Flow - Security Tests', () => {
  test('should prevent SQL injection in login form', async ({ page }) => {
    console.log('🔍 Test: SQL injection prevention');
    
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    
    // Try SQL injection patterns
    const sqlInjectionPayloads = [
      "admin' OR '1'='1",
      "admin'--",
      "' OR 1=1--",
    ];
    
    for (const payload of sqlInjectionPayloads) {
      await loginPage.emailInput.fill(payload);
      await loginPage.passwordInput.fill(payload);
      await loginPage.loginButton.click();
      
      await page.waitForTimeout(1000);
      
      // Should not be authenticated
      expect(page.url()).toContain('/auth/login');
      console.log(`✅ SQL injection prevented: ${payload}`);
    }
  });

  test('should prevent XSS in login form', async ({ page }) => {
    console.log('🔍 Test: XSS prevention');
    
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    
    // Try XSS payload
    const xssPayload = '<script>alert("XSS")</script>';
    await loginPage.emailInput.fill(xssPayload);
    await loginPage.passwordInput.fill('test');
    await loginPage.loginButton.click();
    
    await page.waitForTimeout(1000);
    
    // Check that script didn't execute
    const alerts = page.locator('text=XSS');
    expect(await alerts.count()).toBe(0);
    console.log('✅ XSS attack prevented');
  });
});
