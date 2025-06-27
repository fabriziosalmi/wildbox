// Test script to verify admin endpoints are working
const API_BASE = 'http://localhost/api/v1/identity';

async function getAuthToken() {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'username=superadmin@wildbox.com&password=wildbox123'
  });
  
  if (!response.ok) {
    throw new Error(`Login failed: ${response.status}`);
  }
  
  const data = await response.json();
  return data.access_token;
}

async function testAdminEndpoints() {
  try {
    console.log('Getting auth token...');
    const token = await getAuthToken();
    console.log('✓ Authentication successful');
    
    // Test admin users endpoint
    console.log('\nTesting admin users endpoint...');
    const usersResponse = await fetch(`${API_BASE}/users/admin/users?limit=10`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (usersResponse.ok) {
      const users = await usersResponse.json();
      console.log(`✓ Admin users endpoint working - found ${users.length} users`);
      console.log(`  First user: ${users[0]?.email}`);
    } else {
      console.error(`✗ Admin users endpoint failed: ${usersResponse.status}`);
      const error = await usersResponse.text();
      console.error(`  Error: ${error}`);
    }
    
    // Test analytics endpoint  
    console.log('\nTesting analytics endpoint...');
    const analyticsResponse = await fetch(`${API_BASE}/analytics/admin/analytics/system-stats?days=30`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (analyticsResponse.ok) {
      const analytics = await analyticsResponse.json();
      console.log('✓ Analytics endpoint working');
      console.log(`  Total users: ${analytics.users?.total}`);
      console.log(`  Active users: ${analytics.users?.active}`);
    } else {
      console.error(`✗ Analytics endpoint failed: ${analyticsResponse.status}`);
    }
    
  } catch (error) {
    console.error('Test failed:', error.message);
  }
}

testAdminEndpoints();
