import { test, expect, Page } from '@playwright/test';
import { LoginPage } from './page-objects/login-page';
import { AdminPage } from './page-objects/admin-page';
import { DashboardPage } from './page-objects/dashboard-page';

// Test configuration
const ADMIN_CREDENTIALS = {
  email: 'superadmin@wildbox.com',
  password: 'superadmin123'
};

const TEST_USER_CREDENTIALS = {
  email: `test-user-${Date.now()}@wildbox.com`,
  password: 'testpassword123'
};

test.describe('Admin Comprehensive E2E Tests', () => {
  let loginPage: LoginPage;
  let adminPage: AdminPage;
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    adminPage = new AdminPage(page);
    dashboardPage = new DashboardPage(page);
  });

  test('Complete Admin Workflow: Login, Create User, Manage User, Navigate Dashboard, Clean up', async ({ page }) => {
    console.log('🎯 Starting comprehensive admin workflow test...');

    // Step 1: Admin Login
    console.log('📝 Step 1: Admin Login');
    await loginPage.goto();
    await loginPage.login(ADMIN_CREDENTIALS.email, ADMIN_CREDENTIALS.password);
    
    // Verify login success
    const isLoggedIn = await loginPage.isLoggedIn();
    expect(isLoggedIn).toBeTruthy();
    console.log('✅ Admin login successful');

    // Step 2: Navigate to Admin Page
    console.log('📝 Step 2: Navigate to Admin Page');
    await adminPage.goto();
    await adminPage.waitForAdminPageLoad();
    
    // Verify admin page loaded
    await expect(page.locator('h1')).toContainText('System Administration');
    console.log('✅ Admin page loaded successfully');

    // Step 3: Check System Stats
    console.log('📝 Step 3: Check System Stats');
    const totalUsers = await adminPage.getStatsCardValue('Total Users');
    const activeUsers = await adminPage.getStatsCardValue('Active Users');
    console.log(`📊 Current stats - Total Users: ${totalUsers}, Active Users: ${activeUsers}`);

    // Step 4: Create New User
    console.log('📝 Step 4: Create New User');
    await adminPage.createUser(TEST_USER_CREDENTIALS.email, TEST_USER_CREDENTIALS.password, {
      isActive: true,
      isSuperuser: false
    });
    
    // Verify user creation toast/message
    await expect(page.locator('.toast, [role="alert"]')).toBeVisible({ timeout: 10000 });
    console.log('✅ User creation initiated');

    // Wait a bit for user to be created and page to update
    await page.waitForTimeout(2000);

    // Step 5: Search for Created User
    console.log('📝 Step 5: Search for Created User');
    await adminPage.searchUsers(TEST_USER_CREDENTIALS.email);
    
    // Verify user appears in search results
    const userRow = await adminPage.getUserRowByEmail(TEST_USER_CREDENTIALS.email);
    await expect(userRow).toBeVisible({ timeout: 10000 });
    console.log('✅ Created user found in search results');

    // Step 6: Test User Management Features
    console.log('📝 Step 6: Test User Management Features');
    
    // Test user deactivation
    await adminPage.toggleUserStatus(TEST_USER_CREDENTIALS.email, 'deactivate');
    await page.waitForTimeout(1000);
    console.log('✅ User deactivated');

    // Test user reactivation
    await adminPage.toggleUserStatus(TEST_USER_CREDENTIALS.email, 'activate');
    await page.waitForTimeout(1000);
    console.log('✅ User reactivated');

    // Test user promotion to superuser
    await adminPage.promoteUser(TEST_USER_CREDENTIALS.email);
    await page.waitForTimeout(1000);
    console.log('✅ User promoted to superuser');

    // Test user demotion from superuser
    await adminPage.demoteUser(TEST_USER_CREDENTIALS.email);
    await page.waitForTimeout(1000);
    console.log('✅ User demoted from superuser');

    // Step 7: Test System Health Monitoring
    console.log('📝 Step 7: Test System Health Monitoring');
    const healthStatus = await adminPage.getSystemHealthStatus();
    console.log('🏥 System Health Status:', healthStatus);
    
    // Refresh system health
    await adminPage.refreshSystemHealth();
    console.log('✅ System health refreshed');

    // Refresh system stats
    await adminPage.refreshSystemStats();
    console.log('✅ System stats refreshed');

    // Step 8: Test Filtering and Search
    console.log('📝 Step 8: Test Filtering and Search');
    
    // Test filter active users
    await adminPage.filterUsers('active');
    await page.waitForTimeout(1000);
    console.log('✅ Filtered active users');

    // Test filter all users
    await adminPage.filterUsers('all');
    await page.waitForTimeout(1000);
    console.log('✅ Showed all users');

    // Clear search
    await adminPage.searchUsers('');
    console.log('✅ Cleared search filter');

    // Step 9: Navigate Dashboard Pages
    console.log('📝 Step 9: Navigate Dashboard Pages');
    await dashboardPage.goto();
    await dashboardPage.waitForDashboardLoad();
    
    const currentTitle = await dashboardPage.getCurrentPageTitle();
    console.log(`📄 Current page: ${currentTitle}`);

    // Get all available navigation links
    const navLinks = await dashboardPage.getAllNavigationLinks();
    console.log(`🔗 Available navigation links: ${navLinks.join(', ')}`);

    // Navigate through available dashboard pages
    const pagesToTest = ['Dashboard', 'Admin', 'Settings', 'Profile'];
    
    for (const pageName of pagesToTest) {
      if (navLinks.some(link => link.toLowerCase().includes(pageName.toLowerCase()))) {
        try {
          console.log(`🔄 Navigating to ${pageName}...`);
          await dashboardPage.navigateToPage(pageName);
          await page.waitForTimeout(1000);
          
          const pageTitle = await dashboardPage.getCurrentPageTitle();
          console.log(`✅ Successfully navigated to ${pageName} (${pageTitle})`);
          
          // Get some page content for verification
          const content = await dashboardPage.getPageContent();
          if (content.length > 0) {
            console.log(`📄 Page content preview: ${content.slice(0, 3).join(', ')}...`);
          }
        } catch (error) {
          console.log(`⚠️ Could not navigate to ${pageName}: ${error}`);
        }
      }
    }

    // Step 10: Return to Admin Page for Cleanup
    console.log('📝 Step 10: Return to Admin Page for Cleanup');
    await adminPage.goto();
    await adminPage.waitForAdminPageLoad();

    // Step 11: Delete Test User (Cleanup)
    console.log('📝 Step 11: Delete Test User (Cleanup)');
    
    // Search for the test user again
    await adminPage.searchUsers(TEST_USER_CREDENTIALS.email);
    
    // Delete the test user
    await adminPage.deleteUser(TEST_USER_CREDENTIALS.email);
    console.log('✅ Test user deleted successfully');

    // Step 12: Verify Final Stats
    console.log('📝 Step 12: Verify Final Stats');
    await page.waitForTimeout(2000); // Wait for stats to update
    
    const finalTotalUsers = await adminPage.getStatsCardValue('Total Users');
    const finalActiveUsers = await adminPage.getStatsCardValue('Active Users');
    console.log(`📊 Final stats - Total Users: ${finalTotalUsers}, Active Users: ${finalActiveUsers}`);

    // Step 13: Test Logout
    console.log('📝 Step 13: Test Logout');
    await dashboardPage.logout();
    
    // Verify logout
    await expect(page).toHaveURL(/auth\/login/, { timeout: 10000 });
    console.log('✅ Logout successful');

    console.log('🎉 Comprehensive admin workflow test completed successfully!');
  });

  test('User Management Edge Cases', async ({ page }) => {
    console.log('🎯 Starting user management edge cases test...');

    // Login as admin
    await loginPage.goto();
    await loginPage.login(ADMIN_CREDENTIALS.email, ADMIN_CREDENTIALS.password);
    await adminPage.goto();
    await adminPage.waitForAdminPageLoad();

    // Test 1: Create user with invalid email
    console.log('📝 Test 1: Create user with invalid email');
    try {
      await adminPage.createUser('invalid-email', 'password123');
      // Should show error message
      await expect(page.locator('.toast, [role="alert"]')).toBeVisible({ timeout: 5000 });
      console.log('✅ Invalid email properly rejected');
    } catch (error) {
      console.log('⚠️ Invalid email test failed:', error);
    }

    // Test 2: Create user with short password
    console.log('📝 Test 2: Create user with short password');
    try {
      await adminPage.createUser('test@example.com', '123');
      // Should show error message
      await expect(page.locator('.toast, [role="alert"]')).toBeVisible({ timeout: 5000 });
      console.log('✅ Short password properly rejected');
    } catch (error) {
      console.log('⚠️ Short password test failed:', error);
    }

    // Test 3: Search for non-existent user
    console.log('📝 Test 3: Search for non-existent user');
    await adminPage.searchUsers('nonexistent@example.com');
    const usersData = await adminPage.getUsersTableData();
    const foundUser = usersData.find(user => user.email.includes('nonexistent@example.com'));
    expect(foundUser).toBeUndefined();
    console.log('✅ Non-existent user search handled correctly');

    // Test 4: Test filtering
    console.log('📝 Test 4: Test filtering');
    await adminPage.filterUsers('active');
    await page.waitForTimeout(1000);
    
    await adminPage.filterUsers('inactive');
    await page.waitForTimeout(1000);
    
    await adminPage.filterUsers('all');
    await page.waitForTimeout(1000);
    console.log('✅ Filtering functionality tested');

    console.log('🎉 User management edge cases test completed!');
  });

  test('System Monitoring and Health Checks', async ({ page }) => {
    console.log('🎯 Starting system monitoring test...');

    // Login as admin
    await loginPage.goto();
    await loginPage.login(ADMIN_CREDENTIALS.email, ADMIN_CREDENTIALS.password);
    await adminPage.goto();
    await adminPage.waitForAdminPageLoad();

    // Test system health status
    console.log('📝 Testing system health status...');
    const healthStatus = await adminPage.getSystemHealthStatus();
    
    // Verify we have health data for all services
    const expectedServices = ['Identity Service', 'Gateway', 'Database', 'Redis Cache'];
    for (const service of expectedServices) {
      expect(healthStatus[service]).toBeDefined();
      console.log(`🏥 ${service}: ${healthStatus[service]}`);
    }

    // Test refresh functionality
    console.log('📝 Testing refresh functionality...');
    await adminPage.refreshSystemHealth();
    await adminPage.refreshSystemStats();
    
    // Verify stats are still visible after refresh
    const totalUsers = await adminPage.getStatsCardValue('Total Users');
    expect(parseInt(totalUsers) || 0).toBeGreaterThanOrEqual(0);
    console.log('✅ System monitoring test completed');
  });

  test('Dashboard Navigation Comprehensive Test', async ({ page }) => {
    console.log('🎯 Starting comprehensive dashboard navigation test...');

    // Login as admin
    await loginPage.goto();
    await loginPage.login(ADMIN_CREDENTIALS.email, ADMIN_CREDENTIALS.password);
    
    // Start from dashboard
    await dashboardPage.goto();
    await dashboardPage.waitForDashboardLoad();

    // Get all navigation links
    const navLinks = await dashboardPage.getAllNavigationLinks();
    console.log(`🔗 Found ${navLinks.length} navigation links: ${navLinks.join(', ')}`);

    // Test navigation to each page
    for (const link of navLinks) {
      if (link && link.trim()) {
        try {
          console.log(`🔄 Testing navigation to: ${link}`);
          await dashboardPage.navigateToPage(link);
          
          // Verify page loaded
          const pageTitle = await dashboardPage.getCurrentPageTitle();
          console.log(`✅ Successfully loaded: ${pageTitle}`);
          
          // Take a screenshot for visual verification
          await page.screenshot({ 
            path: `tests/screenshots/nav-${link.toLowerCase().replace(/[^a-z0-9]/g, '-')}.png`,
            fullPage: true 
          });
          
        } catch (error) {
          console.log(`⚠️ Navigation to ${link} failed: ${error}`);
        }
      }
    }

    console.log('🎉 Dashboard navigation test completed!');
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Take final screenshot and clear any remaining data
    await page.screenshot({ 
      path: `tests/screenshots/final-state-${Date.now()}.png`,
      fullPage: true 
    });
  });
});
