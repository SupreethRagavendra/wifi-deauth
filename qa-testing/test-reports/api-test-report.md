# Module 1 - API Test Report

**Test Date:** January 25, 2026  
**Test Tool:** Newman (Postman CLI)  
**Backend URL:** http://localhost:8080  
**Total Duration:** 8.7 seconds

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| **Total Requests** | 25 |
| **Total Assertions** | 39 |
| **Passed Assertions** | 35 (89.7%) |
| **Failed Assertions** | 4 (10.3%) |
| **Average Response Time** | 330ms |
| **Min Response Time** | 5ms |
| **Max Response Time** | 1050ms |

---

## ✅ Passed Tests

### 1. Admin Registration
| Test Case | Status | Response Time |
|-----------|--------|---------------|
| Register Admin - Success | ✅ PASS | 1050ms |
| Register Admin - Invalid Email | ✅ PASS | 6ms |
| Register Admin - Weak Password | ✅ PASS | 9ms |
| Register Admin - Missing Required Fields | ✅ PASS | 8ms |

### 2. Home User Registration
| Test Case | Status | Response Time |
|-----------|--------|---------------|
| Register Home User - Success | ✅ PASS | 910ms |
| Register Home User - Invalid Email | ✅ PASS | 7ms |
| Register Home User - Weak Password | ✅ PASS | 7ms |

### 3. Viewer Registration
| Test Case | Status | Response Time |
|-----------|--------|---------------|
| Verify Institute Code - Valid | ✅ PASS | 391ms |
| Verify Institute Code - Invalid | ✅ PASS | 390ms |
| Register Viewer - Invalid Institute Code | ✅ PASS | 343ms |

### 4. Login Tests
| Test Case | Status | Response Time |
|-----------|--------|---------------|
| Create User for Login Test | ✅ PASS | 921ms |
| Login - Invalid Credentials | ✅ PASS | 368ms |
| Login - Invalid Email Format | ✅ PASS | 5ms |
| Login - Missing Password | ✅ PASS | 8ms |
| Login - Missing Email | ✅ PASS | 8ms |
| Login - Empty Body | ✅ PASS | 5ms |

### 5. Security Tests
| Test Case | Status | Response Time |
|-----------|--------|---------------|
| SQL Injection Test - Email | ✅ PASS | 13ms |
| Large Payload Test | ✅ PASS | 10ms |

### 6. Edge Cases
| Test Case | Status | Response Time |
|-----------|--------|---------------|
| Unicode Characters in Name | ✅ PASS | 936ms |
| Email with Plus Sign | ✅ PASS | 989ms |
| Password at Minimum Length | ✅ PASS | 904ms |
| Empty String vs Null | ✅ PASS | 7ms |

---

## ❌ Failed Tests

### 1. API Health Check
- **Endpoint:** `GET /api/auth/login`
- **Expected:** 200, 401, 403, or 404
- **Actual:** 500 Internal Server Error
- **Issue:** GET method not supported on login endpoint, returns 500 instead of 405 Method Not Allowed
- **Priority:** 🟡 Medium
- **Recommendation:** Return 405 Method Not Allowed for unsupported HTTP methods

### 2. Register Admin - Invalid Institute Type
- **Endpoint:** `POST /api/auth/register/admin`
- **Expected:** 400 Bad Request
- **Actual:** 500 Internal Server Error
- **Issue:** Invalid enum value causes server crash instead of validation error
- **Priority:** 🔴 High
- **Recommendation:** Add proper validation for InstituteType enum with user-friendly error message

### 3. User Role Naming Inconsistency
- **Endpoint:** `POST /api/auth/register/home`
- **Expected Role:** `HOME`
- **Actual Role:** `HOME_USER`
- **Issue:** API returns `HOME_USER` but frontend/tests expect `HOME`
- **Priority:** 🟡 Medium
- **Recommendation:** Standardize role naming across frontend and backend

### 4. XSS Payload Not Sanitized
- **Endpoint:** `POST /api/auth/register/home`
- **Issue:** `<script>` tag accepted and stored in user name field
- **Priority:** 🔴 High (Security)
- **Recommendation:** 
  - Implement input sanitization/escaping for all user inputs
  - Add HTML entity encoding before storing in database
  - Consider using a library like OWASP Java HTML Sanitizer

---

## 🔍 Detailed Bug Analysis

### BUG-001: Invalid Enum Causes 500 Error
```
Location: AuthController.registerAdmin()
Input: { "instituteType": "INVALID_TYPE" }
Response: 500 Internal Server Error
Root Cause: Spring doesn't handle invalid enum deserialization gracefully
Fix: Add @JsonCreator with custom error handling in InstituteType enum
```

### BUG-002: XSS Vulnerability in Name Field
```
Location: User entity, name field
Input: { "name": "<script>alert('XSS')</script>" }
Response: 201 Created (XSS stored)
Root Cause: No input sanitization
Fix: Add @SafeHtml annotation or use HtmlUtils.htmlEscape()
```

### BUG-003: GET on Login Returns 500
```
Location: AuthController.login()
Input: GET /api/auth/login
Response: 500 Internal Server Error
Root Cause: Unhandled HttpRequestMethodNotSupportedException
Fix: Add global exception handler for method not allowed
```

---

## 📈 Performance Analysis

| Endpoint Category | Avg Response Time | Status |
|------------------|-------------------|--------|
| Registration (Admin) | 1050ms | ⚠️ Slow |
| Registration (Home) | 910ms | ⚠️ Slow |
| Validation Errors | 5-10ms | ✅ Fast |
| Institute Code Verification | 390ms | ⚠️ Moderate |
| Login (Auth) | 368ms | ⚠️ Moderate |

**Observations:**
- Registration endpoints are slow (~1 second) - likely due to password hashing
- Validation error responses are very fast (good)
- Database queries seem to add ~300-400ms overhead

---

## 🛡️ Security Summary

| Test | Result |
|------|--------|
| SQL Injection Prevention | ✅ Protected |
| XSS Prevention | ❌ Vulnerable |
| Password Validation | ✅ Working |
| Email Validation | ✅ Working |
| Large Payload Handling | ✅ Protected |

---

## 📋 Recommendations

### Critical (Fix Immediately)
1. **XSS Vulnerability** - Add input sanitization for all text fields
2. **Enum Validation** - Handle invalid enum values with proper error messages

### Important (Fix Soon)
3. **HTTP Method Handling** - Return 405 for unsupported methods
4. **Role Naming** - Standardize role names between frontend and backend
5. **Response Time** - Consider caching or async processing for registration

### Nice to Have
6. **Error Messages** - Make error messages more user-friendly
7. **Rate Limiting** - Add rate limiting to prevent brute force attacks

---

## 📁 Test Collection Location

- **Collection File:** `/qa-testing/postman/module1-auth-collection.json`
- **Results File:** `/qa-testing/postman/test-results.json`

---

## ✍️ Sign-off

- **Tester:** Automated (Newman)
- **Date:** January 25, 2026
- **Status:** ⚠️ Requires Bug Fixes Before Production
