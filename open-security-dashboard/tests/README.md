# E2E Testing Suite for Wildbox Dashboard

This comprehensive end-to-end testing suite uses Playwright to simulate real admin usage scenarios including login, user management, dashboard navigation, and system monitoring.

## 🎯 What the Tests Cover

### 1. Complete Admin Workflow
- **Admin Login**: Tests login with superadmin credentials
- **User Creation**: Creates test users with various permissions
- **User Management**: 
  - Activate/deactivate users
  - Promote/demote superuser privileges
  - Search and filter users
  - Delete users (with cleanup)
- **Dashboard Navigation**: Tests all available dashboard pages
- **System Monitoring**: Checks system health and statistics
- **Logout**: Verifies proper session cleanup

### 2. Edge Cases & Validation
- Invalid email format handling
- Password strength validation
- Non-existent user searches
- Filtering functionality
- Error message validation

### 3. System Health Monitoring
- Service status checks (Identity, Gateway, Database, Redis)
- Stats refresh functionality
- Real-time monitoring capabilities

## 🚀 Getting Started

### Prerequisites

1. **Services Running**: Make sure all services are running:
   ```bash
   # Start the dashboard
   npm run dev
   
   # Start other services (identity, gateway, etc.)
   # Check docker-compose or individual service startup commands
   ```

2. **Admin Account**: Ensure the superadmin account exists:
   - Email: `superadmin@wildbox.com`
   - Password: `superadmin123`

### Installation

The testing dependencies are already installed. If you need to reinstall:

```bash
npm install --save-dev @playwright/test
npx playwright install
```

## 🧪 Running Tests

### Quick Start

```bash
# Run all admin tests (headless)
npm run test:admin

# Run with browser visible (headed mode)
npm run test:admin:headed

# Run all E2E tests
npm run test:e2e

# Run with Playwright UI (interactive)
npm run test:e2e:ui

# Debug mode (step through tests)
npm run test:e2e:debug
```

### Using the Test Runner Script

```bash
# Run the comprehensive test suite with service checks
./run-admin-tests.sh
```

This script will:
- Check if required services are running
- Run the admin comprehensive tests
- Generate an HTML report
- Take screenshots of test execution
- Open the test report automatically (on macOS)

### Individual Test Commands

```bash
# Run specific test file
npx playwright test admin-comprehensive.spec.ts

# Run with specific browser
npx playwright test --project=chromium
npx playwright test --project=firefox
npx playwright test --project=webkit

# Run in headed mode (see browser)
npx playwright test --headed

# Run specific test by name
npx playwright test -g "Complete Admin Workflow"
```

## 📁 Test Structure

```
tests/
├── e2e/
│   ├── page-objects/
│   │   ├── admin-page.ts      # Admin page interactions
│   │   ├── login-page.ts      # Login page interactions
│   │   └── dashboard-page.ts  # Dashboard navigation
│   └── admin-comprehensive.spec.ts  # Main test file
├── screenshots/               # Test screenshots
└── playwright-report/        # Generated test reports
```

### Page Objects

The tests use the Page Object Model for maintainability:

- **LoginPage**: Handles authentication
- **AdminPage**: Manages admin panel interactions
- **DashboardPage**: Handles dashboard navigation

## 🎬 Test Scenarios

### Main Test: "Complete Admin Workflow"

1. **Login** as superadmin
2. **Navigate** to admin page
3. **Check** current system stats
4. **Create** a new test user
5. **Search** for the created user
6. **Manage** user (deactivate/activate, promote/demote)
7. **Monitor** system health
8. **Test** filtering and search
9. **Navigate** through dashboard pages
10. **Delete** test user (cleanup)
11. **Verify** final stats
12. **Logout**

### Additional Tests

- **User Management Edge Cases**: Invalid inputs, error handling
- **System Monitoring**: Health checks, stats refresh
- **Dashboard Navigation**: Comprehensive page testing

## 📊 Test Reports

After running tests, you'll find:

- **HTML Report**: `playwright-report/index.html`
- **Screenshots**: `tests/screenshots/`
- **Videos**: (for failed tests)
- **Traces**: (for debugging)

## 🔧 Configuration

### Playwright Configuration (`playwright.config.ts`)

```typescript
export default defineConfig({
  testDir: './tests/e2e',
  baseURL: 'http://localhost:3000',
  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  // Tests against Chromium, Firefox, and WebKit
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  // Auto-start dev server
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
  },
});
```

## 🐛 Debugging

### Debug Mode
```bash
npm run test:e2e:debug
```

This opens Playwright Inspector where you can:
- Step through tests
- Inspect elements
- View network requests
- See console logs

### Screenshots & Videos

Failed tests automatically capture:
- Screenshots at the point of failure
- Video recordings of the entire test
- Network traces for debugging

### Common Issues

1. **Services Not Running**
   ```
   ❌ Dashboard not running on localhost:3000
   ```
   **Solution**: Start the dashboard with `npm run dev`

2. **Identity Service Unavailable**
   ```
   ❌ Identity service not running on localhost
   ```
   **Solution**: Start the identity service and gateway

3. **Timeout Errors**
   - Increase timeout in test configuration
   - Check if services are responding slowly
   - Verify network connectivity

## 🔄 Continuous Integration

For CI/CD environments:

```bash
# Install browsers in CI
npx playwright install --with-deps

# Run tests in CI mode
CI=true npx playwright test

# Generate junit reports for CI
npx playwright test --reporter=junit
```

## 📝 Writing New Tests

### Adding Test Cases

1. Create new test files in `tests/e2e/`
2. Use existing page objects or create new ones
3. Follow the pattern of existing tests

### Example Test Structure

```typescript
test('New Admin Feature', async ({ page }) => {
  const loginPage = new LoginPage(page);
  const adminPage = new AdminPage(page);
  
  // Login
  await loginPage.goto();
  await loginPage.login('superadmin@wildbox.com', 'superadmin123');
  
  // Test your feature
  await adminPage.goto();
  // ... test logic
  
  // Assertions
  await expect(page.locator('...')).toBeVisible();
});
```

## 🎯 Best Practices

1. **Use Data Test IDs**: Add `data-testid` attributes for reliable element selection
2. **Page Object Model**: Keep page interactions in page object classes
3. **Cleanup**: Always clean up test data
4. **Waits**: Use proper waits instead of hard timeouts
5. **Screenshots**: Take screenshots for visual verification
6. **Error Handling**: Handle expected errors gracefully

## 🛠️ Maintenance

### Updating Tests

When UI changes:
1. Update selectors in page objects
2. Add new data-testid attributes if needed
3. Update test expectations
4. Run tests to verify changes

### Test Data Management

The tests create temporary users with timestamps to avoid conflicts:
```typescript
const TEST_USER_CREDENTIALS = {
  email: `test-user-${Date.now()}@wildbox.com`,
  password: 'testpassword123'
};
```

## 🚀 Advanced Features

### Parallel Execution
Tests run in parallel by default for faster execution.

### Cross-Browser Testing
Tests run on Chromium, Firefox, and WebKit automatically.

### Mobile Testing
Uncomment mobile configurations in `playwright.config.ts` for mobile testing.

### API Testing
Playwright can also test APIs directly alongside UI tests.

---

**Happy Testing! 🎉**

This comprehensive test suite ensures your admin functionality works perfectly across all scenarios. The tests are designed to catch regressions early and provide confidence in your admin workflow.
