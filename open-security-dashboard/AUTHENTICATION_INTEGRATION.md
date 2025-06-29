# Dashboard Authentication Integration Update

## 🎯 Overview

This document outlines the changes made to integrate the **open-security-dashboard** with the new **open-security-identity** microservice.

## 🔴 Issues Fixed

### 1. Endpoint Path Mismatches
**Before:**
- Dashboard expected: `/api/v1/users/login` and `/api/v1/users/register`
- Dashboard expected: `/api/v1/users/me`

**After:**
- Updated to use: `/api/v1/auth/jwt/login` and `/api/v1/auth/register`
- Updated to use: `/api/v1/auth/me`

### 2. Authentication Protocol Mismatch
**Before:**
- Dashboard sent JSON: `{email, password}`
- Expected response: `{access_token, user}`

**After:**
- Login uses OAuth2 form data: `username=email&password=password`
- Response: `{access_token, token_type, expires_in}`
- User info fetched separately from `/api/v1/auth/me`

### 3. User Data Schema Updates
**Before:**
- User had `name` field
- Teams were simple objects
- Different subscription structure

**After:**
- User schema aligned with identity service
- Team memberships with proper relationships
- Updated subscription and API key schemas

## 📁 Files Modified

### 1. `src/components/auth-provider.tsx`
- **Login Function**: Updated to use form data and separate user fetch
- **Register Function**: Updated endpoint and response handling
- **Token Validation**: Updated endpoint for user info validation
- **Imports**: Removed unused TypeScript interfaces

### 2. `src/hooks/use-auth.ts`
- **API Client**: Changed from `apiClient` to `identityClient`
- **Endpoints**: Updated all user-related endpoints to `/api/v1/auth/*`

### 3. `src/types/index.ts`
- **User Interface**: Updated to match identity service schema
- **Team Interface**: Updated with `owner_id` and proper relationships
- **TeamMembership**: Updated to match new structure
- **Subscription**: Updated to use `team_id` and `plan_id`
- **ApiKey**: Updated field names to match backend
- **Auth Types**: Updated login/register request/response types

## 🔧 Key Changes

### Authentication Flow
```javascript
// OLD FLOW
1. POST /api/v1/users/login {email, password}
2. Response: {access_token, user}

// NEW FLOW  
1. POST /api/v1/auth/jwt/login (form data: username=email&password=password)
2. Response: {access_token, token_type, expires_in}
3. GET /api/v1/auth/me (with Bearer token)
4. Response: {user data with team_memberships}
```

### Environment Configuration
The dashboard already has the correct environment variable:
```bash
NEXT_PUBLIC_IDENTITY_API_URL=http://localhost:8001
```

## 🧪 Testing

A test script has been created: `test_auth_integration.sh`

To test the integration:

```bash
# 1. Start the identity service
cd open-security-identity
make dev

# 2. Test the authentication endpoints
cd ../open-security-dashboard
./test_auth_integration.sh

# 3. Start the dashboard
npm run dev

# 4. Visit http://localhost:3000/auth/login
# Use test@dashboard.com / testpassword123
```

## ✅ Verification Checklist

- [x] Login endpoint uses correct path and form data
- [x] Register endpoint uses correct path
- [x] User info endpoint updated
- [x] TypeScript types match backend schema
- [x] Token storage and validation updated
- [x] Environment variables configured
- [x] Test script created

## 🔄 Migration Notes

### For Existing Users
- Existing tokens will be invalidated (different JWT structure)
- Users will need to log in again
- User data structure may appear different (team memberships vs teams)

### For Developers
- The `identityClient` is now used for all auth operations
- User object structure has changed - check component implementations
- API key structure has updated field names

## 🚀 Next Steps

1. **Start Both Services**:
   ```bash
   # Terminal 1: Identity Service
   cd open-security-identity && make dev
   
   # Terminal 2: Dashboard  
   cd open-security-dashboard && npm run dev
   ```

2. **Test Complete Flow**:
   - User registration
   - User login
   - Dashboard access
   - Token refresh/validation

3. **Update Other Components** (if needed):
   - Profile components that display user info
   - Team management components
   - API key management components

## 🛡️ Security Considerations

- JWT tokens now include team and role information
- API keys are team-scoped (not user-scoped)
- Proper OAuth2 form data for login (more secure)
- Separate user info fetch reduces token payload size

## 📖 API Documentation

The identity service provides comprehensive API documentation at:
- Swagger UI: http://localhost:8001/docs
- ReDoc: http://localhost:8001/redoc

Reference the identity service's `README.md` and `IMPLEMENTATION_COMPLETE.md` for detailed API usage.
