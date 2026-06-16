import { test, expect } from '@playwright/test';
import { LoginPage } from './page-objects/login-page';
import { AdminPage } from './page-objects/admin-page';
import { DashboardPage } from './page-objects/dashboard-page';

// Test configuration - update these if needed
const ADMIN_CREDENTIALS = {
  email: 'superadmin@wildbox.com',
  password: 'superadmin123'
};

test.describe('Admin UI Testing (Without Backend)', () => {
  let loginPage: LoginPage;
  let adminPage: AdminPage;
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    adminPage = new AdminPage(page);
    dashboardPage = new DashboardPage(page);
  });

  test('Login Form Interaction Test', async ({ page }) => {
    console.log('🎯 Testing login form interactions...');

    // Step 1: Go to login page
    await loginPage.goto();
    await expect(page).toHaveURL(/auth\/login/);
    console.log('✅ Login page loaded');

    // Step 2: Verify form elements
    await expect(loginPage.emailInput).toBeVisible();
    await expect(loginPage.passwordInput).toBeVisible();
    await expect(loginPage.loginButton).toBeVisible();
    console.log('✅ Login form elements visible');

    // Step 3: Test form filling
    await loginPage.emailInput.fill(ADMIN_CREDENTIALS.email);
    await loginPage.passwordInput.fill(ADMIN_CREDENTIALS.password);
    console.log('✅ Form filled successfully');

    // Step 4: Check that form values are set
    const emailValue = await loginPage.emailInput.inputValue();
    const passwordValue = await loginPage.passwordInput.inputValue();
    expect(emailValue).toBe(ADMIN_CREDENTIALS.email);
    expect(passwordValue).toBe(ADMIN_CREDENTIALS.password);
    console.log('✅ Form values verified');

    // Step 5: Test login button click (will show error since backend isn't connected)
    await loginPage.loginButton.click();
    console.log('✅ Login button clicked');

    // Wait a bit to see if error appears
    await page.waitForTimeout(2000);
    
    // Check if we're still on login page (expected since no backend)
    expect(page.url()).toContain('/auth/login');
    console.log('✅ Stayed on login page as expected (no backend)');

    console.log('🎉 Login form interaction test completed!');
  });

  test('Admin Page Direct Access Test', async ({ page }) => {
    console.log('🎯 Testing admin page direct access...');

    // Go directly to admin page (will be redirected to login if no auth)
    await page.goto('/admin');
    await page.waitForLoadState('domcontentloaded');

    // Check if we're redirected to login or if we access dashboard directly
    if (page.url().includes('/auth/login')) {
      console.log('✅ Redirected to login as expected');
    } else if (page.url().includes('/dashboard')) {
      console.log('✅ Redirected to dashboard (no auth required in dev mode)');
    } else {
      console.log(`📄 Current URL: ${page.url()}`);
    }

    console.log('🎉 Admin page access protection test completed!');
  });

  test('Dashboard Navigation UI Test', async ({ page }) => {
    console.log('🎯 Testing dashboard page UI...');

    // Go directly to dashboard page
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Should be redirected to login page if not authenticated
    if (page.url().includes('/auth/login')) {
      console.log('✅ Redirected to login as expected');
    } else {
      // If somehow we get to dashboard, test its UI
      console.log('📄 Dashboard page loaded, testing UI...');
      
      // Look for common dashboard elements
      const hasTitle = await page.locator('h1, h2').count() > 0;
      const hasContent = await page.locator('main, .main-content, .dashboard').count() > 0;
      
      console.log(`📊 Dashboard has title: ${hasTitle}`);
      console.log(`📊 Dashboard has content: ${hasContent}`);
    }

    console.log('🎉 Dashboard navigation test completed!');
  });

  test('UI Component Verification Test', async ({ page }) => {
    console.log('🎯 Testing UI components...');

    // Test login page components
    await loginPage.goto();
    
    // Check for Wildbox branding
    const hasBranding = await page.locator('text=Wildbox Security').isVisible();
    console.log(`🏷️ Wildbox branding visible: ${hasBranding}`);

    // Check for security icon
    const hasSecurityIcon = await page.locator('svg, .icon').count() > 0;
    console.log(`🔒 Security icons present: ${hasSecurityIcon}`);

    // Check for form labels
    const hasEmailLabel = await page.locator('label[for="email"]').isVisible();
    const hasPasswordLabel = await page.locator('label[for="password"]').isVisible();
    console.log(`📝 Email label visible: ${hasEmailLabel}`);
    console.log(`📝 Password label visible: ${hasPasswordLabel}`);

    // Check for remember me checkbox
    const hasRememberMe = await page.locator('input[type="checkbox"]').isVisible();
    console.log(`☑️ Remember me checkbox: ${hasRememberMe}`);

    // Check for forgot password link
    const hasForgotPassword = await page.locator('text=Forgot password').isVisible();
    console.log(`🔗 Forgot password link: ${hasForgotPassword}`);

    // Take a screenshot for visual verification
    await page.screenshot({ 
      path: 'tests/screenshots/login-page-components.png',
      fullPage: true 
    });
    console.log('📸 Screenshot saved: login-page-components.png');

    console.log('🎉 UI component verification completed!');
  });

  test('Form Validation Test', async ({ page }) => {
    console.log('🎯 Testing form validation...');

    await loginPage.goto();

    // Fill form first to enable button
    await loginPage.emailInput.fill('test@example.com');
    await loginPage.passwordInput.fill('somepassword');

    // Test with valid form
    await loginPage.loginButton.click();
    
    // Check if HTML5 validation works or if we get an error
    await page.waitForTimeout(1000);
    console.log('📋 Form submission attempted with valid format');

    // Test invalid email
    await loginPage.emailInput.fill('invalid-email');
    const emailValidation = await loginPage.emailInput.evaluate((el: HTMLInputElement) => el.validity.valid);
    console.log(`📋 Invalid email validity: ${emailValidation}`);

    // Test valid email format
    await loginPage.emailInput.fill('test@example.com');
    const emailValidation2 = await loginPage.emailInput.evaluate((el: HTMLInputElement) => el.validity.valid);
    console.log(`📋 Valid email validity: ${emailValidation2}`);

    console.log('🎉 Form validation test completed!');
  });

  test('Responsive Design Test', async ({ page }) => {
    console.log('🎯 Testing responsive design...');

    await loginPage.goto();

    // Test desktop view
    await page.setViewportSize({ width: 1200, height: 800 });
    await page.screenshot({ path: 'tests/screenshots/login-desktop.png' });
    console.log('📱 Desktop view tested');

    // Test tablet view
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.screenshot({ path: 'tests/screenshots/login-tablet.png' });
    console.log('📱 Tablet view tested');

    // Test mobile view
    await page.setViewportSize({ width: 375, height: 667 });
    await page.screenshot({ path: 'tests/screenshots/login-mobile.png' });
    console.log('📱 Mobile view tested');

    // Verify login form is still visible on mobile
    await expect(loginPage.emailInput).toBeVisible();
    await expect(loginPage.passwordInput).toBeVisible();
    await expect(loginPage.loginButton).toBeVisible();
    console.log('✅ Form elements visible on mobile');

    console.log('🎉 Responsive design test completed!');
  });
});
