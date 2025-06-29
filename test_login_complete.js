#!/usr/bin/env node

// Test script to simulate the browser login flow
const { execSync } = require('child_process');

console.log('🧪 Testing the complete login flow...\n');

// Step 1: Login and get token
console.log('1. 🔑 Testing login endpoint...');
try {
  const loginResult = execSync(`curl -s -X POST http://localhost:80/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test@example.com&password=testpass123"`, 
    { encoding: 'utf8' });
  
  const loginData = JSON.parse(loginResult);
  if (loginData.access_token) {
    console.log('✅ Login successful, got token');
    
    // Step 2: Test /me endpoint with token
    console.log('\n2. 👤 Testing user data endpoint...');
    const userResult = execSync(`curl -s -H "Authorization: Bearer ${loginData.access_token}" http://localhost:80/auth/users/me`, 
      { encoding: 'utf8' });
    
    const userData = JSON.parse(userResult);
    if (userData.email) {
      console.log('✅ User data fetch successful:', userData.email);
      
      // Step 3: Test dashboard access
      console.log('\n3. 🏠 Testing dashboard access...');
      const dashboardResult = execSync(`curl -s -H "Authorization: Bearer ${loginData.access_token}" http://localhost:3000/dashboard`, 
        { encoding: 'utf8' });
      
      if (dashboardResult.includes('<!DOCTYPE html>')) {
        console.log('✅ Dashboard page accessible');
      } else {
        console.log('❌ Dashboard page not accessible');
      }
      
    } else {
      console.log('❌ User data fetch failed:', userResult);
    }
  } else {
    console.log('❌ Login failed:', loginResult);
  }
} catch (error) {
  console.error('❌ Test failed:', error.message);
}

console.log('\n🏁 Test complete');
