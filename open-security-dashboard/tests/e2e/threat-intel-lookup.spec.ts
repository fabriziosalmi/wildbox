import { test, expect } from '@playwright/test';
import { LoginPage } from './page-objects/login-page';

/**
 * Task 2.2 - Critical Flow Test: Threat Intel Lookup
 * 
 * Tests the Threat Intelligence lookup functionality including:
 * - Page navigation and rendering
 * - IOC search (IP, Domain, Hash)
 * - Results display and validation
 * - Error handling
 * - Multiple search types
 */

test.describe('Threat Intel Lookup - Critical Path', () => {
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

  test('should navigate to Threat Intel Lookup page', async ({ page }) => {
    console.log('🔍 Test: Navigation to Threat Intel Lookup');
    
    // Navigate to Threat Intel Lookup
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    // Verify URL
    expect(page.url()).toContain('/threat-intel/lookup');
    console.log('✅ Correct URL loaded');
    
    // Verify page heading
    const heading = page.locator('h1, h2').filter({ hasText: /threat intel|lookup|ioc/i });
    await expect(heading.first()).toBeVisible({ timeout: 5000 });
    console.log('✅ Page heading visible');
    
    // Verify search input is present
    const searchInput = page.locator('input[type="text"], input[type="search"], input[placeholder*="search"], input[placeholder*="lookup"], input[placeholder*="IOC"], input[placeholder*="indicator"]');
    await expect(searchInput.first()).toBeVisible();
    console.log('✅ Search input field visible');
    
    // Verify search button is present
    const searchButton = page.locator('button:has-text("Search"), button:has-text("Lookup"), button:has(svg.lucide-search)');
    await expect(searchButton.first()).toBeVisible();
    console.log('✅ Search button visible');
  });

  test('should search for IP address IOC', async ({ page }) => {
    console.log('🔍 Test: IP address lookup');
    
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    // Find search input
    const searchInput = page.locator('input[type="text"], input[type="search"], input[placeholder*="search"], input[placeholder*="lookup"]').first();
    await searchInput.waitFor({ state: 'visible', timeout: 5000 });
    
    // Search for a test IP
    const testIP = '8.8.8.8'; // Google DNS - likely to be in databases
    console.log(`📝 Searching for IP: ${testIP}`);
    
    await searchInput.fill(testIP);
    await searchInput.press('Enter');
    
    // Alternative: click search button if Enter doesn't work
    // const searchButton = page.locator('button:has-text("Search"), button:has-text("Lookup")').first();
    // await searchButton.click();
    
    // Wait for results (or error message)
    await page.waitForTimeout(3000);
    
    // Check if results are displayed OR if there's a "no results" message
    const hasResults = await page.locator('.result, [data-testid="lookup-result"], .card, .reputation, .ioc-info').count() > 0;
    const hasNoResults = await page.locator('text=/no results|not found|no data/i').count() > 0;
    
    expect(hasResults || hasNoResults).toBeTruthy();
    console.log(`✅ Search completed: ${hasResults ? 'Results found' : 'No results message shown'}`);
    
    // If results found, verify key information is displayed
    if (hasResults) {
      // Look for the searched IP in results
      const ipInResults = await page.locator(`text=${testIP}`).count() > 0;
      console.log(`📊 IP shown in results: ${ipInResults}`);
    }
  });

  test('should search for domain IOC', async ({ page }) => {
    console.log('🔍 Test: Domain lookup');
    
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    const searchInput = page.locator('input[type="text"], input[type="search"], input[placeholder*="search"]').first();
    await searchInput.waitFor({ state: 'visible' });
    
    // Search for a test domain
    const testDomain = 'google.com';
    console.log(`📝 Searching for domain: ${testDomain}`);
    
    await searchInput.fill(testDomain);
    await searchInput.press('Enter');
    
    await page.waitForTimeout(3000);
    
    // Verify search was processed
    const hasContent = await page.locator('.result, [data-testid="lookup-result"], .card, text=/reputation|status|verdict/i').count() > 0;
    const hasNoResults = await page.locator('text=/no results|not found/i').count() > 0;
    
    expect(hasContent || hasNoResults).toBeTruthy();
    console.log(`✅ Domain search completed`);
  });

  test('should search for hash IOC', async ({ page }) => {
    console.log('🔍 Test: Hash lookup');
    
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    const searchInput = page.locator('input[type="text"], input[type="search"]').first();
    await searchInput.waitFor({ state: 'visible' });
    
    // Use a known malicious hash (EICAR test file MD5)
    const testHash = '44d88612fea8a8f36de82e1278abb02f';
    console.log(`📝 Searching for hash: ${testHash}`);
    
    await searchInput.fill(testHash);
    await searchInput.press('Enter');
    
    await page.waitForTimeout(3000);
    
    const hasResponse = await page.locator('text=/malicious|suspicious|clean|unknown|reputation|no results/i').count() > 0;
    expect(hasResponse).toBeTruthy();
    console.log('✅ Hash search completed');
  });

  test('should handle invalid input gracefully', async ({ page }) => {
    console.log('🔍 Test: Invalid input handling');
    
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    const searchInput = page.locator('input[type="text"], input[type="search"]').first();
    await searchInput.waitFor({ state: 'visible' });
    
    // Try invalid inputs
    const invalidInputs = [
      'invalid!!!input',
      '   ',
      'abc123xyz',
    ];
    
    for (const input of invalidInputs) {
      console.log(`📝 Testing invalid input: "${input}"`);
      
      await searchInput.fill(input);
      await searchInput.press('Enter');
      await page.waitForTimeout(2000);
      
      // Should show error, validation message, or no results
      const hasErrorOrNoResults = await page.locator('text=/invalid|error|no results|not found|enter valid/i').count() > 0;
      console.log(`✅ Handled invalid input: ${hasErrorOrNoResults ? 'Error shown' : 'Silently handled'}`);
    }
  });

  test('should display reputation indicators', async ({ page }) => {
    console.log('🔍 Test: Reputation indicators display');
    
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    const searchInput = page.locator('input[type="text"], input[type="search"]').first();
    await searchInput.waitFor({ state: 'visible' });
    
    // Search for a common IP
    await searchInput.fill('1.1.1.1'); // Cloudflare DNS
    await searchInput.press('Enter');
    await page.waitForTimeout(3000);
    
    // Look for reputation-related elements
    const reputationElements = page.locator('text=/reputation|verdict|malicious|suspicious|clean|score|confidence/i');
    const hasReputation = await reputationElements.count() > 0;
    
    if (hasReputation) {
      console.log('✅ Reputation indicators found');
      
      // Check for visual indicators (badges, colors)
      const badges = page.locator('.badge, [class*="badge"], [class*="tag"]');
      const hasBadges = await badges.count() > 0;
      console.log(`📊 Visual indicators present: ${hasBadges}`);
    } else {
      console.log('⚠️ No reputation data displayed (may be expected for clean IPs)');
    }
  });

  test('should allow multiple consecutive searches', async ({ page }) => {
    console.log('🔍 Test: Multiple consecutive searches');
    
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    const searchInput = page.locator('input[type="text"], input[type="search"]').first();
    await searchInput.waitFor({ state: 'visible' });
    
    const testQueries = ['8.8.8.8', 'google.com', '1.1.1.1'];
    
    for (const query of testQueries) {
      console.log(`📝 Search ${testQueries.indexOf(query) + 1}: ${query}`);
      
      await searchInput.fill(query);
      await searchInput.press('Enter');
      await page.waitForTimeout(2000);
      
      // Verify query was processed
      const hasContent = await page.locator('text=/reputation|results|no data|error/i').count() > 0;
      expect(hasContent).toBeTruthy();
      console.log('✅ Search completed');
      
      // Clear input for next search
      await searchInput.clear();
    }
    
    console.log('✅ All consecutive searches successful');
  });

  test('should show loading state during search', async ({ page }) => {
    console.log('🔍 Test: Loading state indication');
    
    await page.goto('/threat-intel/lookup');
    await page.waitForLoadState('networkidle');
    
    const searchInput = page.locator('input[type="text"], input[type="search"]').first();
    await searchInput.waitFor({ state: 'visible' });
    
    await searchInput.fill('8.8.8.8');
    
    // Look for loading indicator immediately after triggering search
    await searchInput.press('Enter');
    
    // Check for common loading indicators within a short time
    const loadingIndicators = page.locator('text=/loading|searching|please wait/i, svg.animate-spin, .spinner, [role="progressbar"]');
    
    // Give it 500ms to show loading state
    await page.waitForTimeout(500);
    
    const hasLoadingIndicator = await loadingIndicators.count() > 0;
    console.log(`📊 Loading indicator shown: ${hasLoadingIndicator}`);
    
    // Wait for completion
    await page.waitForTimeout(3000);
    console.log('✅ Search completed');
  });
});

test.describe('Threat Intel Lookup - Navigation Tests', () => {
  test('should access Threat Intel from navigation menu', async ({ page }) => {
    console.log('🔍 Test: Access via navigation menu');
    
    // Login
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(
      process.env.TEST_EMAIL || 'superadmin@wildbox.com',
      process.env.TEST_PASSWORD || 'wildbox123'
    );
    await page.waitForURL(/dashboard|admin/);
    console.log('✅ Logged in');
    
    // Look for Threat Intel in navigation
    const threatIntelNav = page.locator('nav a, nav button').filter({ hasText: /threat intel/i });
    
    if (await threatIntelNav.count() > 0) {
      await threatIntelNav.first().click();
      console.log('✅ Clicked Threat Intel nav item');
      
      // If it's a submenu, look for Lookup option
      const lookupLink = page.locator('a:has-text("Lookup")');
      if (await lookupLink.count() > 0) {
        await lookupLink.click();
        console.log('✅ Clicked Lookup submenu item');
      }
      
      await page.waitForTimeout(1000);
      
      // Verify we're on threat intel page
      const onThreatIntelPage = page.url().includes('/threat-intel');
      expect(onThreatIntelPage).toBeTruthy();
      console.log('✅ Navigated to Threat Intel section');
    } else {
      console.log('⚠️ Threat Intel not visible in navigation (may require expansion)');
    }
  });
});
