import { test, expect } from '@playwright/test';
import { LoginPage } from './page-objects/login-page';

test('Quick Login Test', async ({ page }) => {
  const loginPage = new LoginPage(page);
  
  console.log('🔍 Testing login page...');
  
  // Go to login page
  await loginPage.goto();
  
  // Check if page loaded
  await expect(page).toHaveURL(/auth\/login/);
  console.log('✅ Login page loaded');
  
  // Check if email input is visible
  await expect(loginPage.emailInput).toBeVisible();
  console.log('✅ Email input found');
  
  // Check if password input is visible
  await expect(loginPage.passwordInput).toBeVisible();
  console.log('✅ Password input found');
  
  // Check if login button is visible
  await expect(loginPage.loginButton).toBeVisible();
  console.log('✅ Login button found');
  
  // Try filling the form
  await loginPage.emailInput.fill('test@example.com');
  await loginPage.passwordInput.fill('testpassword');
  console.log('✅ Form filling works');
  
  console.log('🎉 Login page elements are working correctly!');
});
