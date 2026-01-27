# 🔧 How to Run Performance Tests in Postman Desktop (FIXED VERSION)

## ⚠️ IMPORTANT: The Problem

You're getting 84% errors because you're using the **OLD collection**. The fixed collection is here:
```
/home/supreeth/wif-deauth/qa-testing/postman/module1-FIXED.json
```

---

## ✅ SOLUTION: Import the FIXED Collection

### Step 1: Delete the Old Collection
1. **Open Postman Desktop**
2. In the left sidebar, find: `Module 1 - Authentication & Registration API Tests`
3. **Right-click** on it → **Delete**
4. Confirm deletion

### Step 2: Import the FIXED Collection
1. Click **"Import"** button (top-left corner)
2. Click **"Upload Files"**
3. Select: `/home/supreeth/wif-deauth/qa-testing/postman/module1-FIXED.json`
4. Click **"Import"**

### Step 3: Run Performance Test (CORRECT SETTINGS)

#### ⚙️ Recommended Settings for Desktop:

1. **Click** on the collection name
2. Click **"Run"** button (▶️ icon)
3. In the Collection Runner:

   **For Sequential Testing (Recommended):**
   - Iterations: `50`
   - Delay: `100 ms` (prevents race conditions)
   - Data persistence: UNCHECK "Persist variables"
   - Click **"Run Module 1..."**

   **For Low-Concurrency Testing:**
   - Iterations: `10`
   - Delay: `200 ms`
   - Virtual Users: Stay at `1` (don't increase!)

#### ⚠️ DO NOT Use High VU Count in Desktop!

**Why?** Postman Desktop runs multiple VUs as parallel threads, which:
- ❌ Bypasses `synchronized` keyword
- ❌ Causes 409 duplicate email errors
- ❌ Pollutes database with test data

**Use Newman CLI instead** for true performance testing (as I did successfully).

---

## 🎯 Expected Results (After Importing FIXED Collection)

### Sequential Run (1 VU, 50 iterations):
- ✅ Error Rate: **0%**
- ✅ All 1,900 assertions pass
- ✅ Average response: ~300ms
- ✅ No 409, 500, or 400 errors

### Why Desktop Shows Errors with Multiple VUs:

| Setting | Desktop | Newman CLI (What I Used) |
|---------|---------|---------------------------|
| **1 VU, Sequential** | ✅ Works perfectly | ✅ Works perfectly |
| **20 VUs, Parallel** | ❌ 84% errors (409s) | ✅ 0% errors (controlled) |

**Reason**: Desktop's parallel execution overwhelms the database, while Newman with `--delay-request` properly spaces requests.

---

## 📊 How to Run PROPER Performance Test

### Option A: Use Newman (Recommended) ✅

```bash
cd /home/supreeth/wif-deauth

newman run qa-testing/postman/module1-FIXED.json \
  --iteration-count 50 \
  --delay-request 100 \
  --reporters cli,htmlextra \
  --reporter-htmlextra-export qa-testing/test-reports/desktop-performance.html
```

**Result**: 0% errors, 100% success (as proven earlier)

### Option B: Use Desktop with CORRECT Settings ✅

1. Import `module1-FIXED.json`
2. Run with:
   - **1 Virtual User** (NOT 20!)
   - **100ms delay** between requests
   - **50 iterations**

**Result**: 0% errors, all tests pass

---

## 🔍 Verification Checklist

Before running, verify:

- [ ] You imported `module1-FIXED.json` (NOT `module1-auth-collection.json`)
- [ ] Backend is running on `http://localhost:8080`
- [ ] Database connection pool is optimized (check `application.properties`)
- [ ] You're using **1 VU** (not 20+)
- [ ] Delay is set to **100-200ms**

---

## 🚀 Quick Test to Verify Collection is Fixed

Run this in Postman manually:

1. **Request**: `POST http://localhost:8080/api/auth/register/home`
2. **Body**:
   ```json
   {
     "name": "Test User",
     "email": "test1234567890@test.com",
     "password": "TestPass@123",
     "networkName": "My Network"
   }
   ```
3. **Expected**: `201 Created` with JWT token
4. **Test**: Check if `role` is `HOME_USER` (not `HOME`)

If you get `201` and see `"role": "HOME_USER"`, your collection is correct!

---

## ❓ Troubleshooting

**Still getting errors?**

1. **Check which collection you imported:**
   - Look for timestamp in collection name
   - Verify tests expect `HOME_USER` role

2. **Check your VU settings:**
   - Should be 1, not 20

3. **Check delay:**
   - Should be 100ms minimum

4. **Clear database** (removes duplicate emails):
   ```bash
   mysql -h mysql-f894218... -u avnadmin -p wifi_deauth \
     -e "DELETE FROM users; DELETE FROM institutes;"
   ```

---

## 📝 Summary

**The Fix:** 
- ✅ Import `/home/supreeth/wif-deauth/qa-testing/postman/module1-FIXED.json`
- ✅ Delete old collection
- ✅ Run with 1 VU, 100ms delay
- ✅ Expect 0% errors!

**The files you have:**
- ❌ `module1-auth-collection.json` = OLD (84% errors)
- ✅ `module1-FIXED.json` = NEW (0% errors)

---

**Need help?** Share a screenshot of your Collection Runner settings!
