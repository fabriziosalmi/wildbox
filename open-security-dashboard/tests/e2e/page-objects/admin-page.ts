import { Page, Locator, expect } from '@playwright/test';

export class AdminPage {
  readonly page: Page;
  readonly adminStatsCards: Locator;
  readonly userManagementTable: Locator;
  readonly createUserButton: Locator;
  readonly createUserForm: Locator;
  readonly searchInput: Locator;
  readonly filterSelect: Locator;
  readonly refreshHealthButton: Locator;
  readonly refreshStatsButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.adminStatsCards = page.locator('[data-testid="admin-stats-cards"]').first();
    this.userManagementTable = page.locator('table').first();
    this.createUserButton = page.getByRole('button', { name: /create user/i });
    this.createUserForm = page.locator('form').first();
    this.searchInput = page.getByPlaceholder('Search users...');
    this.filterSelect = page.locator('select').first();
    this.refreshHealthButton = page.getByRole('button', { name: /refresh health/i });
    this.refreshStatsButton = page.getByRole('button', { name: /refresh stats/i });
  }

  async goto() {
    await this.page.goto('/admin');
    await this.page.waitForLoadState('networkidle');
  }

  async waitForAdminPageLoad() {
    // Wait for admin page elements to be visible
    await expect(this.page.locator('h1')).toContainText('System Administration');
    await this.page.waitForSelector('[data-testid="admin-stats-cards"], .grid', { timeout: 10000 });
  }

  async getStatsCardValue(cardName: string): Promise<string> {
    const cardMap: { [key: string]: string } = {
      'Total Users': '[data-testid="total-users-value"]',
      'Active Users': '[data-testid="active-users-value"]', 
      'Super Admins': '[data-testid="super-admins-value"]',
      'Total Teams': '[data-testid="total-teams-value"]'
    };
    
    const selector = cardMap[cardName];
    if (selector) {
      const element = this.page.locator(selector);
      return await element.textContent() || '0';
    }
    
    // Fallback to original method
    const card = this.page.locator('.grid .p-6').filter({ hasText: cardName });
    const value = await card.locator('.text-2xl.font-bold').textContent();
    return value || '0';
  }

  async createUser(email: string, password: string, options?: { isSuperuser?: boolean; isActive?: boolean }) {
    // Click create user button if form is not visible
    const formVisible = await this.createUserForm.isVisible();
    if (!formVisible) {
      await this.createUserButton.click();
      await expect(this.createUserForm).toBeVisible();
    }

    // Fill form
    await this.page.fill('#email', email);
    await this.page.fill('#password', password);

    // Set checkboxes if provided
    if (options?.isSuperuser !== undefined) {
      const superuserCheckbox = this.page.locator('input[type="checkbox"]').nth(1);
      const isChecked = await superuserCheckbox.isChecked();
      if (isChecked !== options.isSuperuser) {
        await superuserCheckbox.click();
      }
    }

    if (options?.isActive !== undefined) {
      const activeCheckbox = this.page.locator('input[type="checkbox"]').nth(0);
      const isChecked = await activeCheckbox.isChecked();
      if (isChecked !== options.isActive) {
        await activeCheckbox.click();
      }
    }

    // Submit form
    await this.page.getByRole('button', { name: /create user/i }).first().click();
    
    // Wait for success message or error
    await this.page.waitForSelector('.toast, [role="alert"]', { timeout: 10000 });
  }

  async searchUsers(searchTerm: string) {
    await this.searchInput.fill(searchTerm);
    await this.page.getByRole('button', { name: /search/i }).click();
    await this.page.waitForTimeout(1000); // Wait for search results
  }

  async filterUsers(filter: 'all' | 'active' | 'inactive') {
    await this.filterSelect.selectOption(filter);
    await this.page.waitForTimeout(1000); // Wait for filter results
  }

  async getUserRowByEmail(email: string): Promise<Locator> {
    return this.userManagementTable.locator('tr').filter({ hasText: email });
  }

  async toggleUserStatus(email: string, action: 'activate' | 'deactivate') {
    const userRow = await this.getUserRowByEmail(email);
    const actionButton = userRow.getByRole('button', { name: new RegExp(action, 'i') });
    await actionButton.click();
    
    // Wait for confirmation dialog or toast
    await this.page.waitForSelector('.toast, [role="alert"]', { timeout: 10000 });
  }

  async promoteUser(email: string) {
    const userRow = await this.getUserRowByEmail(email);
    const promoteButton = userRow.getByRole('button', { name: /promote/i });
    await promoteButton.click();
    
    // Handle confirmation dialog
    this.page.on('dialog', dialog => dialog.accept());
    await this.page.waitForSelector('.toast, [role="alert"]', { timeout: 10000 });
  }

  async demoteUser(email: string) {
    const userRow = await this.getUserRowByEmail(email);
    const demoteButton = userRow.getByRole('button', { name: /demote/i });
    await demoteButton.click();
    
    // Handle confirmation dialog
    this.page.on('dialog', dialog => dialog.accept());
    await this.page.waitForSelector('.toast, [role="alert"]', { timeout: 10000 });
  }

  async deleteUser(email: string, forceDelete: boolean = false) {
    const userRow = await this.getUserRowByEmail(email);
    const deleteButton = userRow.locator('button').filter({ hasText: /trash/i }).or(
      userRow.locator('button[title*="Delete"]')
    );
    
    await deleteButton.click();
    
    // Handle confirmation dialogs
    this.page.on('dialog', dialog => {
      if (forceDelete && dialog.message().includes('FORCE DELETE')) {
        dialog.accept();
      } else if (!forceDelete) {
        dialog.accept();
      } else {
        dialog.dismiss();
      }
    });
    
    await this.page.waitForSelector('.toast, [role="alert"]', { timeout: 10000 });
  }

  async getSystemHealthStatus(): Promise<{ [key: string]: string }> {
    const healthCard = this.page.locator('.border-dashed').filter({ hasText: 'System Health' });
    
    const services = ['Identity Service', 'Gateway', 'Database', 'Redis Cache'];
    const status: { [key: string]: string } = {};
    
    for (const service of services) {
      const serviceRow = healthCard.locator('div').filter({ hasText: service });
      const statusText = await serviceRow.locator('span').last().textContent();
      status[service] = statusText?.replace('●', '').trim() || 'unknown';
    }
    
    return status;
  }

  async refreshSystemHealth() {
    await this.refreshHealthButton.click();
    await this.page.waitForTimeout(2000); // Wait for refresh
  }

  async refreshSystemStats() {
    await this.refreshStatsButton.click();
    await this.page.waitForTimeout(2000); // Wait for refresh
  }

  async getUsersTableData(): Promise<Array<{ email: string; status: string; plan: string; teams: number }>> {
    const rows = await this.userManagementTable.locator('tbody tr').all();
    const users = [];
    
    for (const row of rows) {
      const cells = await row.locator('td').all();
      if (cells.length >= 4) {
        const email = await cells[0].locator('p').first().textContent() || '';
        const status = await cells[1].locator('text').textContent() || '';
        const plan = await cells[2].locator('text').textContent() || '';
        const teamBadges = await cells[3].locator('.text-xs').count();
        
        users.push({
          email: email.trim(),
          status: status.trim(),
          plan: plan.trim(),
          teams: teamBadges
        });
      }
    }
    
    return users;
  }
}
