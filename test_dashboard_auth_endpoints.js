#!/usr/bin/env node

/**
 * Test script to verify dashboard authentication endpoints
 */

const axios = require('axios');

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost';
const API_KEY = process.env.API_KEY || 'UrZMId_lkb_-9TcWSicVPCVNqSvnwr8e2VS9iXTAfxw';

// Test data
const TEST_EMAIL = 'test-dashboard@example.com';
const TEST_PASSWORD = 'TestPassword123!';
const TEST_NAME = 'Dashboard Test User';

async function testEndpoint(name, url, method = 'GET', data = null, headers = {}) {
  try {
    console.log(`\n🧪 Testing ${name}...`);
    console.log(`   ${method} ${url}`);
    
    const config = {
      method,
      url,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
        ...headers
      }
    };

    if (data) {
      if (method === 'POST' && url.includes('jwt/login')) {
        // Use form data for OAuth2 login
        config.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        config.data = new URLSearchParams(data).toString();
      } else {
        config.data = data;
      }
    }

    const response = await axios(config);
    console.log(`   ✅ Success: ${response.status}`);
    
    if (response.data && typeof response.data === 'object') {
      if (response.data.access_token) {
        console.log(`   🔑 Token received: ${response.data.access_token.substring(0, 20)}...`);
        return { success: true, data: response.data, token: response.data.access_token };
      }
      if (response.data.email) {
        console.log(`   👤 User: ${response.data.email}`);
        return { success: true, data: response.data };
      }
    }
    
    return { success: true, data: response.data };
  } catch (error) {
    console.log(`   ❌ Error: ${error.response?.status || 'Network'} - ${error.response?.data?.message || error.message}`);
    return { success: false, error: error.response?.data || error.message };
  }
}

async function main() {
  console.log('🚀 Testing Dashboard Authentication Endpoints');
  console.log(`📍 Gateway: ${GATEWAY_URL}`);
  console.log(`🔑 API Key: ${API_KEY.substring(0, 20)}...`);

  // Test 1: Registration
  const registerResult = await testEndpoint(
    'User Registration',
    `${GATEWAY_URL}/api/v1/identity/auth/register`,
    'POST',
    { email: TEST_EMAIL, password: TEST_PASSWORD, name: TEST_NAME }
  );

  let authToken = null;
  if (registerResult.success && registerResult.token) {
    authToken = registerResult.token;
  } else if (registerResult.error && registerResult.error.message?.includes('already registered')) {
    console.log('   ℹ️  User already exists, proceeding with login...');
  }

  // Test 2: Login (FastAPI Users style)
  if (!authToken) {
    const loginResult = await testEndpoint(
      'JWT Login (Form Data)',
      `${GATEWAY_URL}/api/v1/identity/auth/jwt/login`,
      'POST',
      { username: TEST_EMAIL, password: TEST_PASSWORD }
    );

    if (loginResult.success && loginResult.token) {
      authToken = loginResult.token;
    }
  }

  if (!authToken) {
    console.log('\n❌ Could not obtain auth token, aborting user tests');
    return;
  }

  // Test 3: Get Current User
  await testEndpoint(
    'Get Current User',
    `${GATEWAY_URL}/api/v1/identity/users/me`,
    'GET',
    null,
    { 'Authorization': `Bearer ${authToken}` }
  );

  // Test 4: Logout
  await testEndpoint(
    'JWT Logout',
    `${GATEWAY_URL}/api/v1/identity/auth/jwt/logout`,
    'POST',
    {},
    { 'Authorization': `Bearer ${authToken}` }
  );

  // Test 5: Test token invalidation
  await testEndpoint(
    'Token Validation After Logout',
    `${GATEWAY_URL}/api/v1/identity/users/me`,
    'GET',
    null,
    { 'Authorization': `Bearer ${authToken}` }
  );

  console.log('\n🎉 Authentication endpoint tests completed!');
}

main().catch(console.error);
