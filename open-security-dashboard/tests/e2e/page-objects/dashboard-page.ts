import { Page, Locator, expect } from '@playwright/test';

export class DashboardPage {
  readonly page: Page;
  readonly sidebar: Locator;
  readonly mainContent: Locator;
  readonly userMenu: Locator;
  readonly navigationLinks: Locator;

  constructor(page: Page) {
    this.page = page;
    this.sidebar = page.locator('nav, .sidebar, aside').first();
    this.mainContent = page.locator('main, .main-content').first();
    this.userMenu = page.locator('[data-testid="user-menu"], .user-menu').first();
    this.navigationLinks = page.locator('nav a, .nav-link');
  }

  async goto() {
    await this.page.goto('/dashboard');
    await this.page.waitForLoadState('networkidle');
  }

  async waitForDashboardLoad() {
    // Wait for dashboard elements to be visible
    await this.page.waitForSelector('h1, h2, .dashboard', { timeout: 10000 });
  }

  async navigateToPage(pageName: string) {
    const linkSelectors = [
      `a[href*="${pageName.toLowerCase()}"]`,
      `a:has-text("${pageName}")`,
      `.nav-link:has-text("${pageName}")`,
      `[data-testid="${pageName.toLowerCase()}-nav"]`
    ];

    for (const selector of linkSelectors) {
      try {
        const link = this.page.locator(selector).first();
        if (await link.isVisible({ timeout: 2000 })) {
          await link.click();
          await this.page.waitForLoadState('networkidle');
          return;
        }
      } catch {
        continue;
      }
    }

    // If no direct link found, try clicking on navigation items
    const navItems = await this.navigationLinks.all();
    for (const item of navItems) {
      const text = await item.textContent();
      if (text && text.toLowerCase().includes(pageName.toLowerCase())) {
        await item.click();
        await this.page.waitForLoadState('networkidle');
        return;
      }
    }

    throw new Error(`Could not find navigation link for ${pageName}`);
  }

  async getAllNavigationLinks(): Promise<string[]> {
    const links = await this.navigationLinks.all();
    const linkTexts = [];
    
    for (const link of links) {
      const text = await link.textContent();
      if (text && text.trim()) {
        linkTexts.push(text.trim());
      }
    }
    
    return linkTexts;
  }

  async isUserMenuVisible(): Promise<boolean> {
    try {
      return await this.userMenu.isVisible({ timeout: 2000 });
    } catch {
      return false;
    }
  }

  async logout() {
    // Try various logout methods
    const logoutSelectors = [
      'button:has-text("Logout")',
      'button:has-text("Sign Out")',
      'a:has-text("Logout")',
      'a:has-text("Sign Out")',
      '[data-testid="logout"]'
    ];

    for (const selector of logoutSelectors) {
      try {
        const element = this.page.locator(selector).first();
        if (await element.isVisible({ timeout: 2000 })) {
          await element.click();
          await this.page.waitForURL(/auth\/login/, { timeout: 5000 });
          return;
        }
      } catch {
        continue;
      }
    }

    // If no logout button found, try user menu
    if (await this.userMenu.isVisible()) {
      await this.userMenu.click();
      await this.page.waitForTimeout(500);
      
      for (const selector of logoutSelectors) {
        try {
          const element = this.page.locator(selector).first();
          if (await element.isVisible({ timeout: 1000 })) {
            await element.click();
            await this.page.waitForURL(/auth\/login/, { timeout: 5000 });
            return;
          }
        } catch {
          continue;
        }
      }
    }

    // Fallback: clear cookies and navigate to login
    await this.page.context().clearCookies();
    await this.page.goto('/auth/login');
  }

  async getCurrentPageTitle(): Promise<string> {
    const titleSelectors = ['h1', 'h2', '[data-testid="page-title"]', '.page-title'];
    
    for (const selector of titleSelectors) {
      try {
        const element = this.page.locator(selector).first();
        const text = await element.textContent({ timeout: 2000 });
        if (text && text.trim()) {
          return text.trim();
        }
      } catch {
        continue;
      }
    }
    
    return await this.page.title() || 'Unknown Page';
  }

  async getPageContent(): Promise<string[]> {
    // Get main content sections
    const contentSelectors = [
      '.card h3',
      '.card h4', 
      '.card p',
      '.grid .p-6 p',
      'main h1',
      'main h2',
      'main h3'
    ];

    const content = [];
    
    for (const selector of contentSelectors) {
      try {
        const elements = await this.page.locator(selector).all();
        for (const element of elements) {
          const text = await element.textContent();
          if (text && text.trim()) {
            content.push(text.trim());
          }
        }
      } catch {
        continue;
      }
    }
    
    return content;
  }
}
