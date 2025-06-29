#!/usr/bin/env node

// Test script to verify the login flow
const axios = require('axios');

async function testLoginFlow() {
    try {
        console.log('🔍 Testing login flow...');
        
        // Test 1: Check if gateway is accessible
        console.log('\n1. Testing gateway accessibility...');
        const gatewayResponse = await axios.get('http://localhost:80/health');
        console.log('✅ Gateway health check:', gatewayResponse.status, gatewayResponse.data);
        
        // Test 2: Check auth endpoints
        console.log('\n2. Testing auth endpoints...');
        const authHealthResponse = await axios.get('http://localhost:80/auth/health');
        console.log('✅ Auth service health check:', authHealthResponse.status, authHealthResponse.data);
        
        // Test 3: Attempt login with test credentials
        console.log('\n3. Testing login...');
        const loginData = {
            email: 'admin@wildbox.local',
            password: 'admin123'
        };
        
        const loginResponse = await axios.post('http://localhost:80/auth/login', loginData, {
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });
        
        console.log('✅ Login response:', loginResponse.status);
        console.log('Response data:', loginResponse.data);
        
        if (loginResponse.data.access_token) {
            console.log('✅ Access token received');
            
            // Test 4: Verify token with /me endpoint
            console.log('\n4. Testing token verification...');
            const meResponse = await axios.get('http://localhost:80/auth/me', {
                headers: {
                    'Authorization': `Bearer ${loginResponse.data.access_token}`
                }
            });
            
            console.log('✅ Token verification:', meResponse.status);
            console.log('User data:', meResponse.data);
        } else {
            console.log('❌ No access token in response');
        }
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
    }
}

testLoginFlow();
