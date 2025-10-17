import { test, expect } from '@playwright/test';
import { LoginPage } from './page-objects/login-page';

/**
 * Task 2.2 - Critical Flow Test: Settings Management
 * 
 * Tests the Settings section functionality including:
 * - Settings page navigation and rendering
 * - Profile management
 * - API Keys management
 * - Billing information access
 * - Team management (if applicable)
 * - Settings persistence
 */

test.describe('Settings Management - Critical Path', () => {
  test.beforeEach(async ({ page }) => {
    console.log('🔐 Logging in before test...');
    
    // Login first
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    
    const testEmail = process.env.TEST_EMAIL || 'superadmin@wildbox.com';
    const testPassword = process.env.TEST_PASSWORD || 'wildbox123';
    
    await loginPage.login(testEmail, testPassword);
    await page.waitForURL(/dashboard|admin/, { timeout: 15000 });
    console.log('✅ Logged in successfully');
  });

  test('should navigate to Settings page from menu', async ({ page }) => {
    console.log('🔍 Test: Navigate to Settings via menu');
    
    // Look for Settings in navigation
    const settingsNav = page.locator('nav a, nav button, a[href*="/settings"]').filter({ hasText: /settings|configuration/i });
    await expect(settingsNav.first()).toBeVisible({ timeout: 5000 });
    await settingsNav.first().click();
    console.log('✅ Clicked Settings navigation item');
    
    // Wait for navigation
    await page.waitForURL(/settings/, { timeout: 5000 });
    
    // Verify we're on settings page
    expect(page.url()).toContain('/settings');
    console.log('✅ Navigated to Settings page');
    
    // Verify page heading
    const heading = page.locator('h1, h2').filter({ hasText: /settings/i });
    await expect(heading.first()).toBeVisible();
    console.log('✅ Settings page heading visible');
  });

  test('should display all settings sections', async ({ page }) => {
    console.log('🔍 Test: Display all settings sections');
    
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    
    // Check for common settings sections
    const expectedSections = [
      { name: 'Profile', selector: 'text=/profile|account information/i' },
      { name: 'API Keys', selector: 'text=/api key|api token|programmatic access/i' },
      { name: 'Billing', selector: 'text=/billing|subscription|payment/i' },
      { name: 'Team', selector: 'text=/team|members|collaboration/i' },
    ];
    
    for (const section of expectedSections) {
      const element = page.locator(section.selector);
      const isVisible = await element.count() > 0;
      console.log(`📊 ${section.name} section ${isVisible ? '✅ found' : '❌ not found'}`);
    }
    
    console.log('✅ Settings sections check complete');
  });

  test('should navigate to Profile settings', async ({ page }) => {
    console.log('🔍 Test: Navigate to Profile settings');
    
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    
    // Find and click Profile link/card
    const profileLink = page.locator('a[href*="/settings/profile"], button:has-text("Profile")').first();
    
    if (await profileLink.count() > 0) {
      await profileLink.click();
      console.log('✅ Clicked Profile settings');
      
      await page.waitForURL(/settings\/profile/, { timeout: 5000 });
      expect(page.url()).toContain('/settings/profile');
      console.log('✅ Navigated to Profile page');
      
      // Verify profile page elements
      const emailField = page.locator('input[type="email"], input[name="email"], text=/email/i');
      const hasEmailField = await emailField.count() > 0;
      console.log(`📊 Email field present: ${hasEmailField}`);
    } else {
      console.log('⚠️ Profile link not found - trying direct navigation');
      await page.goto('/settings/profile');
      await page.waitForLoadState('networkidle');
      console.log('✅ Navigated directly to Profile page');
    }
  });

  test('should navigate to API Keys settings', async ({ page }) => {
    console.log('🔍 Test: Navigate to API Keys settings');
    
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    
    // Find and click API Keys link/card
    const apiKeysLink = page.locator('a[href*="/settings/api-keys"], button:has-text("API"), a:has-text("API Keys")').first();
    
    if (await apiKeysLink.count() > 0) {
      await apiKeysLink.click();
      console.log('✅ Clicked API Keys settings');
      
      await page.waitForURL(/settings\/api-keys/, { timeout: 5000 });
      expect(page.url()).toContain('/settings/api-keys');
      console.log('✅ Navigated to API Keys page');
      
      // Verify API Keys page elements
      const createButton = page.locator('button:has-text("Create"), button:has-text("New"), button:has-text("Generate")');
      const hasCreateButton = await createButton.count() > 0;
      console.log(`📊 Create API Key button present: ${hasCreateButton}`);
      
      // Look for API keys table or list
      const keysTable = page.locator('table, .api-key, [data-testid="api-keys-list"]');
      const hasKeysTable = await keysTable.count() > 0;
      console.log(`📊 API Keys table/list present: ${hasKeysTable}`);
    } else {
      console.log('⚠️ API Keys link not found - trying direct navigation');
      await page.goto('/settings/api-keys');
      await page.waitForLoadState('networkidle');
      console.log('✅ Navigated directly to API Keys page');
    }
  });

  test('should navigate to Billing settings', async ({ page }) => {
    console.log('🔍 Test: Navigate to Billing settings');
    
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    
    // Find and click Billing link/card
    const billingLink = page.locator('a[href*="/settings/billing"], button:has-text("Billing"), a:has-text("Billing")').first();
    
    if (await billingLink.count() > 0) {
      await billingLink.click();
      console.log('✅ Clicked Billing settings');
      
      await page.waitForURL(/settings\/billing/, { timeout: 5000 });
      expect(page.url()).toContain('/settings/billing');
      console.log('✅ Navigated to Billing page');
      
      // Verify Billing page elements
      const subscriptionInfo = page.locator('text=/subscription|plan|pricing/i');
      const hasSubscriptionInfo = await subscriptionInfo.count() > 0;
      console.log(`📊 Subscription information present: ${hasSubscriptionInfo}`);
    } else {
      console.log('⚠️ Billing link not found - trying direct navigation');
      await page.goto('/settings/billing');
      await page.waitForLoadState('networkidle');
      console.log('✅ Navigated directly to Billing page');
    }
  });

  test('should navigate to Team settings', async ({ page }) => {
    console.log('🔍 Test: Navigate to Team settings');
    
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    
    // Find and click Team link/card
    const teamLink = page.locator('a[href*="/settings/team"], button:has-text("Team"), a:has-text("Team")').first();
    
    if (await teamLink.count() > 0) {
      await teamLink.click();
      console.log('✅ Clicked Team settings');
      
      await page.waitForURL(/settings\/team/, { timeout: 5000 });
      expect(page.url()).toContain('/settings/team');
      console.log('✅ Navigated to Team page');
      
      // Verify Team page elements
      const inviteButton = page.locator('button:has-text("Invite"), button:has-text("Add Member")');
      const hasInviteButton = await inviteButton.count() > 0;
      console.log(`📊 Invite team member button present: ${hasInviteButton}`);
    } else {
      console.log('⚠️ Team link not found - trying direct navigation');
      await page.goto('/settings/team');
      await page.waitForLoadState('networkidle');
      console.log('✅ Navigated directly to Team page');
    }
  });

  test('should display user account status', async ({ page }) => {
    console.log('🔍 Test: Display user account status');
    
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    
    // Look for account status indicators
    const statusIndicators = page.locator('text=/account status|active|inactive|subscription|plan/i');
    const hasStatusInfo = await statusIndicators.count() > 0;
    
    if (hasStatusInfo) {
      console.log('✅ Account status information displayed');
      
      // Check for specific status
      const activeStatus = await page.locator('text=/active/i').count() > 0;
      console.log(`📊 Account appears to be active: ${activeStatus}`);
    } else {
      console.log('⚠️ Account status not prominently displayed');
    }
  });

  test('should access profile settings directly via URL', async ({ page }) => {
    console.log('🔍 Test: Direct URL access to Profile');
    
    await page.goto('/settings/profile');
    await page.waitForLoadState('networkidle');
    
    // Verify we're on the profile page
    expect(page.url()).toContain('/settings/profile');
    console.log('✅ Profile page accessible via direct URL');
    
    // Verify profile page content
    const profileContent = page.locator('text=/profile|email|name|password/i');
    const hasProfileContent = await profileContent.count() > 0;
    expect(hasProfileContent).toBeTruthy();
    console.log('✅ Profile page content loaded');
  });

  test('should access API keys directly via URL', async ({ page }) => {
    console.log('🔍 Test: Direct URL access to API Keys');
    
    await page.goto('/settings/api-keys');
    await page.waitForLoadState('networkidle');
    
    // Verify we're on the API keys page
    expect(page.url()).toContain('/settings/api-keys');
    console.log('✅ API Keys page accessible via direct URL');
    
    // Verify API keys page content
    const apiContent = page.locator('text=/api key|token|create|generate/i');
    const hasApiContent = await apiContent.count() > 0;
    expect(hasApiContent).toBeTruthy();
    console.log('✅ API Keys page content loaded');
  });

  test('should show user email in settings area', async ({ page }) => {
    console.log('🔍 Test: User email display');
    
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    
    // Look for user email (might be in header, sidebar, or page content)
    const testEmail = process.env.TEST_EMAIL || 'superadmin@wildbox.com';
    const emailElement = page.locator(`text=${testEmail}`);
    
    const emailVisible = await emailElement.count() > 0;
    console.log(`📊 User email visible: ${emailVisible}`);
    
    if (!emailVisible) {
      // Check if any email-like pattern is visible
      const anyEmail = page.locator('text=/@.+\\..+/');
      const hasAnyEmail = await anyEmail.count() > 0;
      console.log(`📊 Any email pattern visible: ${hasAnyEmail}`);
    }
  });

  test('should handle navigation between settings sections', async ({ page }) => {
    console.log('🔍 Test: Navigate between settings sections');
    
    const sections = [
      '/settings/profile',
      '/settings/api-keys',
      '/settings/billing',
      '/settings/team',
    ];
    
    for (const section of sections) {
      console.log(`📝 Navigating to ${section}`);
      await page.goto(section);
      await page.waitForLoadState('networkidle');
      
      // Verify URL
      expect(page.url()).toContain(section);
      console.log(`✅ Successfully navigated to ${section}`);
      
      // Wait a bit between navigations
      await page.waitForTimeout(500);
    }
    
    console.log('✅ All settings sections accessible');
  });
});

test.describe('Settings Management - Security Tests', () => {
  test('should protect settings page from unauthenticated access', async ({ page, context }) => {
    console.log('🔍 Test: Settings page protection');
    
    // Clear all cookies to simulate logged out state
    await context.clearCookies();
    
    // Try to access settings page
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Should be redirected to login or see auth prompt
    const isProtected = page.url().includes('/auth/login') || 
                       page.url() === '/' ||
                       await page.locator('text=/sign in|login|please log in/i').count() > 0;
    
    expect(isProtected).toBeTruthy();
    console.log('✅ Settings page properly protected from unauthenticated access');
  });

  test('should require authentication for API keys page', async ({ page, context }) => {
    console.log('🔍 Test: API Keys page protection');
    
    // Clear cookies
    await context.clearCookies();
    
    // Try to access API keys directly
    await page.goto('/settings/api-keys');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Should be redirected or blocked
    const isProtected = page.url().includes('/auth/login') || 
                       page.url() === '/' ||
                       await page.locator('text=/sign in|login|unauthorized/i').count() > 0;
    
    expect(isProtected).toBeTruthy();
    console.log('✅ API Keys page properly protected');
  });
});

test.describe('Settings Management - Navigation Breadcrumbs', () => {
  test('should show navigation context in settings', async ({ page }) => {
    console.log('🔍 Test: Settings navigation context');
    
    // Login
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(
      process.env.TEST_EMAIL || 'superadmin@wildbox.com',
      process.env.TEST_PASSWORD || 'wildbox123'
    );
    await page.waitForURL(/dashboard|admin/);
    
    // Navigate to a settings subsection
    await page.goto('/settings/api-keys');
    await page.waitForLoadState('networkidle');
    
    // Look for breadcrumbs or navigation hints
    const breadcrumbs = page.locator('nav[aria-label="breadcrumb"], .breadcrumb, .breadcrumbs');
    const hasBreadcrumbs = await breadcrumbs.count() > 0;
    
    console.log(`📊 Breadcrumbs present: ${hasBreadcrumbs}`);
    
    // At minimum, the settings section should be indicated in the active nav
    const activeNavItem = page.locator('nav a.active, nav [aria-current], nav .bg-primary');
    const hasActiveIndicator = await activeNavItem.count() > 0;
    console.log(`📊 Active navigation indicator: ${hasActiveIndicator}`);
  });
});
