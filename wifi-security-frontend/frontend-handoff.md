# Frontend Handoff Document for Agent 3 (Backend Developer)

## Overview

This document provides all the API specifications needed for the backend implementation. The frontend expects the following endpoints and response formats.

---

## Base URL

```
Development: http://localhost:8080/api
Production: ${REACT_APP_API_URL}/api
```

---

## Authentication Endpoints

### 1. Register Institute Admin

**Endpoint:** `POST /auth/register/admin`

**Request:**
```json
{
  "instituteName": "TechCorp University",
  "instituteType": "COLLEGE",  // Enum: COLLEGE | SCHOOL | COMPANY
  "location": "San Francisco, CA",  // Optional
  "adminName": "John Doe",
  "email": "admin@techcorp.edu",
  "password": "SecurePass123"
}
```

**Response (201 Created):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid-here",
    "email": "admin@techcorp.edu",
    "name": "John Doe",
    "role": "ADMIN",
    "instituteName": "TechCorp University",
    "instituteCode": "TC2024XY",
    "createdAt": "2024-01-20T10:00:00Z"
  },
  "instituteCode": "TC2024XY"
}
```

**Error Response (400 Bad Request):**
```json
{
  "message": "Email already registered"
}
```

---

### 2. Register Viewer

**Endpoint:** `POST /auth/register/viewer`

**Request:**
```json
{
  "instituteCode": "TC2024XY",
  "name": "Jane Smith",
  "email": "jane@example.com",
  "password": "SecurePass123"
}
```

**Response (201 Created):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid-here",
    "email": "jane@example.com",
    "name": "Jane Smith",
    "role": "VIEWER",
    "instituteName": "TechCorp University",
    "instituteCode": "TC2024XY",
    "createdAt": "2024-01-20T11:00:00Z"
  }
}
```

---

### 3. Register Home User

**Endpoint:** `POST /auth/register/home`

**Request:**
```json
{
  "name": "Bob Wilson",
  "email": "bob@home.com",
  "password": "SecurePass123",
  "networkName": "Wilson Home WiFi"  // Optional
}
```

**Response (201 Created):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid-here",
    "email": "bob@home.com",
    "name": "Bob Wilson",
    "role": "HOME_USER",
    "createdAt": "2024-01-20T12:00:00Z"
  }
}
```

---

### 4. Login

**Endpoint:** `POST /auth/login`

**Request:**
```json
{
  "email": "admin@techcorp.edu",
  "password": "SecurePass123"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid-here",
    "email": "admin@techcorp.edu",
    "name": "John Doe",
    "role": "ADMIN",
    "instituteName": "TechCorp University",
    "instituteCode": "TC2024XY",
    "createdAt": "2024-01-20T10:00:00Z"
  }
}
```

**Error Response (401 Unauthorized):**
```json
{
  "message": "Invalid email or password"
}
```

---

### 5. Verify Institute Code

**Endpoint:** `GET /institutes/verify/:code`

**Example:** `GET /institutes/verify/TC2024XY`

**Response (200 OK):**
```json
{
  "code": "TC2024XY",
  "instituteName": "TechCorp University",
  "isValid": true
}
```

**Error Response (404 Not Found):**
```json
{
  "code": "INVALID",
  "instituteName": null,
  "isValid": false
}
```

---

### 6. Get Current User

**Endpoint:** `GET /auth/me`

**Headers:**
```
Authorization: Bearer <jwt-token>
```

**Response (200 OK):**
```json
{
  "id": "uuid-here",
  "email": "admin@techcorp.edu",
  "name": "John Doe",
  "role": "ADMIN",
  "instituteName": "TechCorp University",
  "instituteCode": "TC2024XY",
  "createdAt": "2024-01-20T10:00:00Z"
}
```

---

## HTTP Status Codes

| Code | Description | Usage |
|------|-------------|-------|
| 200 | OK | Successful GET, PUT requests |
| 201 | Created | Successful POST (resource created) |
| 400 | Bad Request | Validation errors, malformed request |
| 401 | Unauthorized | Invalid/expired token, wrong credentials |
| 403 | Forbidden | Authenticated but not authorized |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Duplicate resource (e.g., email exists) |
| 500 | Internal Server Error | Server-side error |

---

## JWT Token Format

**Expected Claims:**
```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "role": "ADMIN",
  "instituteId": "institute-uuid",  // Optional for HOME_USER
  "iat": 1705747200,
  "exp": 1705833600
}
```

**Token Lifetime:** 24 hours recommended

---

## CORS Requirements

The backend must allow CORS from:

- Development: `http://localhost:3000`
- Production: Configured frontend domain

**Required Headers:**
```
Access-Control-Allow-Origin: <frontend-origin>
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
```

---

## Required Headers

**All Requests:**
```
Content-Type: application/json
```

**Authenticated Requests:**
```
Authorization: Bearer <jwt-token>
```

---

## Validation Requirements

### Password:
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 number

### Institute Code:
- Uppercase letters and numbers only
- Generated by backend (recommend 8 characters)

### Email:
- Standard email format validation

---

## User Roles

| Role | Description |
|------|-------------|
| `ADMIN` | Institute administrator with full access |
| `VIEWER` | Organization member with read-only access |
| `HOME_USER` | Personal/home network user |

---

## Database Schema Suggestion

### Users Table
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(100) NOT NULL,
  role ENUM('ADMIN', 'VIEWER', 'HOME_USER') NOT NULL,
  institute_id UUID REFERENCES institutes(id),
  network_name VARCHAR(255),  -- For HOME_USER
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Institutes Table
```sql
CREATE TABLE institutes (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type ENUM('COLLEGE', 'SCHOOL', 'COMPANY') NOT NULL,
  code VARCHAR(20) UNIQUE NOT NULL,
  location VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  admin_id UUID REFERENCES users(id)
);
```

---

## Status

✅ **READY FOR AGENT 3**

Frontend Module 1 is complete and ready for backend integration.
