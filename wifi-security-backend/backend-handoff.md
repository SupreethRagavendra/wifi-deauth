# Backend Handoff Document - Module 1

## ✅ STATUS: READY FOR AGENT 4 TESTING

**Completed:** 2026-01-20
**Agent:** Agent 3 (Backend Developer)
**Module:** Role-Based Registration & Authentication

---

## 🚀 Quick Start

### Prerequisites
- Java 17+
- Maven 3.8+
- MySQL 8.0+ (or use provided Aiven cloud connection)

### Run Locally

```bash
cd wifi-security-backend

# Build the project
./mvnw clean install -DskipTests

# Run the application
./mvnw spring-boot:run
```

The server will start on **http://localhost:8080**

### Database Configuration

The application is configured to use Aiven MySQL cloud:
- **Host:** mysql-f894218-supreethvennila-ef7e.j.aivencloud.com
- **Port:** 27574
- **Database:** wifi_deauth
- **SSL:** Required

To use a local MySQL instead, update `application.properties`:
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/wifi_deauth
spring.datasource.username=root
spring.datasource.password=your_password
```

---

## 📡 API Endpoints

### Base URL: `http://localhost:8080`

### Authentication Endpoints (Public)

#### 1. Register Admin
Creates a new admin with a new institute.

```
POST /api/auth/register/admin
Content-Type: application/json

{
  "instituteName": "MIT College",
  "instituteType": "COLLEGE",
  "location": "Cambridge, MA",
  "adminName": "John Smith",
  "email": "john@mit.edu",
  "password": "SecurePass123"
}

Response (201 Created):
{
  "message": "Admin registered successfully",
  "instituteCode": "MITC2026A1B2",
  "userId": "uuid-here",
  "instituteName": "MIT College"
}
```

#### 2. Register Viewer
Creates a viewer account for an existing institute.

```
POST /api/auth/register/viewer
Content-Type: application/json

{
  "instituteCode": "MITC2026A1B2",
  "name": "Jane Doe",
  "email": "jane@mit.edu",
  "password": "SecurePass123"
}

Response (201 Created):
{
  "token": "eyJhbGc...",
  "userId": "uuid-here",
  "email": "jane@mit.edu",
  "name": "Jane Doe",
  "role": "VIEWER",
  "instituteName": "MIT College",
  "instituteCode": "MITC2026A1B2",
  "instituteType": "COLLEGE",
  "message": "Viewer registered successfully"
}
```

#### 3. Register Home User
Creates a home user with personal "institute".

```
POST /api/auth/register/home
Content-Type: application/json

{
  "name": "Bob Wilson",
  "email": "bob@home.com",
  "password": "SecurePass123",
  "networkName": "Home WiFi"
}

Response (201 Created):
{
  "token": "eyJhbGc...",
  "userId": "uuid-here",
  "email": "bob@home.com",
  "name": "Bob Wilson",
  "role": "ADMIN",
  "instituteName": "Bob Wilson's Home Network",
  "instituteCode": null,
  "instituteType": "HOME",
  "message": "Home user registered successfully"
}
```

#### 4. Login
Authenticate and get JWT token.

```
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@mit.edu",
  "password": "SecurePass123"
}

Response (200 OK):
{
  "token": "eyJhbGc...",
  "userId": "uuid-here",
  "email": "john@mit.edu",
  "name": "John Smith",
  "role": "ADMIN",
  "instituteName": "MIT College",
  "instituteCode": "MITC2026A1B2",
  "instituteType": "COLLEGE",
  "message": "Login successful"
}
```

#### 5. Verify Institute Code
Check if an institute code is valid.

```
POST /api/auth/verify-institute-code
Content-Type: application/json

{
  "instituteCode": "MITC2026A1B2"
}

Response (200 OK):
{
  "valid": true,
  "instituteName": "MIT College",
  "instituteType": "COLLEGE"
}
```

### Protected Endpoints (Require JWT)

Add header: `Authorization: Bearer <token>`

#### 6. Get Current User Profile

```
GET /api/users/me

Response (200 OK):
{
  "userId": "uuid-here",
  "name": "John Smith",
  "email": "john@mit.edu",
  "role": "ADMIN",
  "instituteName": "MIT College",
  "instituteCode": "MITC2026A1B2",
  "instituteType": "COLLEGE",
  "createdAt": "2026-01-20T10:30:00"
}
```

#### 7. Get Viewers (Admin Only)

```
GET /api/users/viewers

Response (200 OK):
[
  {
    "userId": "uuid-here",
    "name": "Jane Doe",
    "email": "jane@mit.edu",
    "role": "VIEWER",
    ...
  }
]
```

#### 8. Get Institute Details (Admin Only)

```
GET /api/institutes/my

Response (200 OK):
{
  "instituteId": "uuid-here",
  "instituteName": "MIT College",
  "instituteType": "COLLEGE",
  "instituteCode": "MITC2026A1B2",
  "location": "Cambridge, MA",
  "createdAt": "2026-01-20T10:30:00"
}
```

#### 9. WiFi Network CRUD

```
# Create WiFi (Admin only)
POST /api/wifi
{
  "ssid": "MIT-Guest",
  "bssid": "AA:BB:CC:DD:EE:FF",
  "channel": 6,
  "securityType": "WPA2",
  "location": "Building A"
}

# Get WiFi networks
GET /api/wifi
# Admin: sees all institute networks
# Viewer: sees only assigned networks

# Delete WiFi (Admin only)
DELETE /api/wifi/{wifiId}

# Assign WiFi to Viewer (Admin only)
POST /api/wifi/assign-to-viewer
{
  "viewerId": "viewer-uuid",
  "wifiId": "wifi-uuid"
}
```

---

## 🔐 Security Details

### JWT Token
- **Algorithm:** HS256
- **Expiration:** 24 hours (86400000 ms)
- **Claims:**
  - `sub`: User email
  - `role`: ADMIN or VIEWER
  - `userId`: User UUID
  - `instituteId`: Institute UUID (nullable for home)

### Password Requirements
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 number
- Hashed with BCrypt (strength 12)

### Institute Code Format
- Pattern: `[PREFIX][YEAR][RANDOM]`
- Example: `MITC2026A1B2`
- Prefix: First 4 letters of institute name
- Year: 4 digits
- Random: 4 alphanumeric characters

---

## 📋 Error Codes

| HTTP Status | Error | Description |
|-------------|-------|-------------|
| 400 | Bad Request | Validation errors |
| 401 | Unauthorized | Invalid credentials or expired token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Duplicate email |
| 500 | Internal Server Error | Unexpected error |

### Error Response Format
```json
{
  "error": "Conflict",
  "message": "Email already registered: john@mit.edu",
  "status": 409,
  "timestamp": "2026-01-20 10:30:00",
  "path": "/api/auth/register/admin"
}
```

---

## 🧪 Test Credentials

Create these test accounts for testing:

### Admin Account
```json
{
  "instituteName": "Test University",
  "instituteType": "COLLEGE",
  "adminName": "Test Admin",
  "email": "testadmin@test.com",
  "password": "TestPass123"
}
```

### Viewer Account
```json
{
  "instituteCode": "<from admin registration>",
  "name": "Test Viewer",
  "email": "testviewer@test.com",
  "password": "TestPass123"
}
```

### Home User
```json
{
  "name": "Test Home",
  "email": "testhome@test.com",
  "password": "TestPass123"
}
```

---

## 📁 Project Structure

```
wifi-security-backend/
├── pom.xml
├── src/main/java/com/wifi/security/
│   ├── Application.java
│   ├── config/
│   │   ├── SecurityConfig.java
│   │   ├── JwtTokenProvider.java
│   │   ├── JwtAuthenticationFilter.java
│   │   └── CorsConfig.java
│   ├── controller/
│   │   ├── AuthController.java
│   │   ├── UserController.java
│   │   ├── InstituteController.java
│   │   └── WiFiController.java
│   ├── dto/
│   │   ├── request/ (5 DTOs)
│   │   └── response/ (5 DTOs)
│   ├── entity/ (4 entities)
│   ├── enums/ (3 enums)
│   ├── exception/ (6 files)
│   ├── repository/ (4 repos)
│   ├── service/ (3 services)
│   └── util/ (3 utilities)
├── src/main/resources/
│   ├── application.properties
│   └── schema.sql
└── src/test/java/...
```

---

## ✅ Checklist

- [x] Database schema created (MySQL)
- [x] All 4 entities with relationships
- [x] All 4 repositories with custom methods
- [x] All DTOs with validation
- [x] Security configured (JWT + BCrypt strength 12)
- [x] All 5 auth endpoints working
- [x] Exception handling (global)
- [x] Institute code generation (unique)
- [x] Role-based authorization
- [x] CORS configured (localhost:3000, localhost:5173)
- [x] Logging implemented
- [x] Unit tests created
- [x] Integration tests created

---

## ⚠️ Known Limitations

1. **Rate limiting not implemented** - Should be added for production
2. **Email verification not implemented** - Can be added in future
3. **Password reset not implemented** - Can be added in future

---

## 🔗 Frontend Integration

The backend is configured to accept requests from:
- `http://localhost:3000` (React default)
- `http://localhost:5173` (Vite default)

CORS is fully configured with all necessary headers.

---

## 📝 Notes for Agent 4

1. Run `./mvnw spring-boot:run` to start the server
2. Server runs on port 8080
3. All endpoints are tested with Postman collection
4. Check logs for any database connection issues
5. JWT secret is configured in application.properties (change for production)
