# 🛡️ CyberShield — Cyber Security API Intelligence Dashboard

> **Group A — Final Semester eProject**  
> A professional-grade cybersecurity intelligence platform integrating 20 free security APIs.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [20 Integrated APIs](#20-integrated-apis)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [API Keys Setup](#api-keys-setup)
- [Running the Project](#running-the-project)
- [API Endpoints](#api-endpoints)
- [Database Collections](#database-collections)
- [Screenshots](#screenshots)

---

## Overview

CyberShield is a full-stack cybersecurity dashboard that allows registered users to search, explore, and test 20 free security intelligence APIs. It features JWT authentication, MongoDB Atlas storage, activity tracking, bookmarking, and a professional dark-themed UI.

---

## Features

| Feature | Description |
|---|---|
| 🔐 **Auth System** | JWT + bcrypt registration & login |
| 🗄️ **MongoDB Atlas** | Users, activity logs, tool catalog |
| 🔍 **20 Security APIs** | Full integration with real endpoints |
| 📊 **Dashboard** | Cards, search, filter, test panel |
| 🔖 **Bookmarks** | Save favorite APIs |
| 📜 **Activity Log** | Track all user actions in DB |
| 👤 **Profile Page** | View stats, bookmarks, history |
| 📱 **Responsive UI** | Mobile-friendly cyberpunk design |
| ⚡ **API Test Panel** | Execute queries from the UI |

---

## Tech Stack

**Frontend:** HTML5, CSS3, Vanilla JavaScript, Font Awesome  
**Backend:** Node.js, Express.js  
**Database:** MongoDB Atlas  
**Auth:** JWT (jsonwebtoken) + bcryptjs  
**HTTP Client:** Axios  
**Dev Tools:** Nodemon, dotenv

---

## 20 Integrated APIs

| # | API | Category | Key Required |
|---|---|---|---|
| 1 | AbuseIPDB | IP Intelligence | ✅ Free key |
| 2 | VirusTotal | Malware Analysis | ✅ Free key |
| 3 | Have I Been Pwned | Breach Detection | ✅ Paid key |
| 4 | IPinfo | IP Intelligence | ✅ Free key |
| 5 | Shodan | Threat Detection | ✅ Free key |
| 6 | SecurityTrails | DNS Analysis | ✅ Free key |
| 7 | WhoisXML | WHOIS Lookup | ✅ Free key |
| 8 | GreyNoise | Threat Detection | ✅ Free key |
| 9 | URLScan | URL Scanning | ✅ Free key |
| 10 | Hunter.io | Email Intelligence | ✅ Free key |
| 11 | BuiltWith | Threat Detection | ✅ Free key |
| 12 | Censys | IP Intelligence | ✅ Free key |
| 13 | OpenPhish | URL Scanning | ❌ No key needed |
| 14 | AlienVault OTX | Threat Detection | ✅ Free key |
| 15 | NVD API | Vulnerability | ❌ No key needed |
| 16 | IPAPI | Geolocation | ❌ No key needed |
| 17 | EmailRep | Email Intelligence | ✅ Free key |
| 18 | DNS Lookup | DNS Analysis | ❌ No key needed |
| 19 | Google Safe Browsing | URL Scanning | ✅ Free key |
| 20 | CVE Details | Vulnerability | ❌ No key needed |

---

## Project Structure

```
CyberSecurity-Dashboard/
│
├── backend/
│   ├── server.js                  # Express app entry point
│   ├── .env                       # Environment variables
│   ├── package.json
│   │
│   ├── config/
│   │   └── db.js                  # MongoDB Atlas connection
│   │
│   ├── models/
│   │   ├── User.js                # User schema
│   │   ├── SecurityTool.js        # Tool catalog schema
│   │   └── Activity.js            # Activity log schema
│   │
│   ├── controllers/
│   │   ├── authController.js      # Register, Login, Profile
│   │   ├── apiController.js       # All 20 API integrations
│   │   └── activityController.js  # Log, fetch, stats
│   │
│   ├── routes/
│   │   ├── authRoutes.js          # /api/auth/*
│   │   ├── apiRoutes.js           # /api/security/*
│   │   └── activityRoutes.js      # /api/activity/*
│   │
│   └── middleware/
│       └── authMiddleware.js      # JWT protect middleware
│
├── frontend/
│   ├── index.html                 # Landing page
│   ├── login.html                 # Login page
│   ├── register.html              # Register page
│   ├── dashboard.html             # Main dashboard
│   ├── profile.html               # User profile
│   │
│   ├── css/
│   │   └── style.css              # Full cyberpunk theme
│   │
│   └── js/
│       └── utils.js               # Shared utilities
│
└── README.md
```

---

## Installation & Setup

### Prerequisites
- Node.js v18+
- MongoDB Atlas account (free tier works)
- API keys (see below)

### 1. Clone / Extract Project

```bash
cd CyberSecurity-Dashboard
```

### 2. Install Backend Dependencies

```bash
cd backend
npm install
```

### 3. Configure Environment Variables

Edit `backend/.env`:

```env
PORT=5000
MONGO_URI=mongodb+srv://USERNAME:PASSWORD@cluster0.xxxxx.mongodb.net/cybershield
JWT_SECRET=your_super_secret_key_here
JWT_EXPIRE=7d
```

---

## API Keys Setup

Get free API keys from each provider:

| API | Sign Up URL | Free Tier |
|---|---|---|
| AbuseIPDB | https://www.abuseipdb.com/register | 1,000 checks/day |
| VirusTotal | https://www.virustotal.com/gui/sign-in | 500 requests/day |
| IPinfo | https://ipinfo.io/signup | 50,000/month |
| Shodan | https://account.shodan.io/register | Limited free |
| SecurityTrails | https://securitytrails.com/app/signup | 50 queries/month |
| WhoisXML | https://www.whoisxmlapi.com/signup | 500 queries |
| GreyNoise | https://www.greynoise.io/signup | Community free |
| URLScan | https://urlscan.io/user/login | Free |
| Hunter.io | https://hunter.io/users/sign_up | 25 searches/month |
| AlienVault OTX | https://otx.alienvault.com/api | Free |
| Google Safe Browsing | https://console.cloud.google.com | Free |
| EmailRep | https://emailrep.io/key | Free |

> **APIs that need NO key:** OpenPhish, NVD, IPAPI, DNS Lookup, CVE Details

---

## Running the Project

```bash
# From /backend directory:

# Development (with auto-restart)
npm run dev

# Production
npm start
```

Then open: **http://localhost:5000**

The server serves both the backend API and the frontend static files.

---

## API Endpoints

### Auth Routes (`/api/auth`)

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/api/auth/register` | Register new user | Public |
| POST | `/api/auth/login` | Login user | Public |
| GET | `/api/auth/profile` | Get user profile | 🔒 JWT |
| PUT | `/api/auth/profile` | Update profile | 🔒 JWT |

### Security API Routes (`/api/security`) — All require JWT

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/security/abuseipdb?query=IP` | Check malicious IP |
| GET | `/api/security/virustotal?query=URL` | Scan URL/domain |
| GET | `/api/security/hibp?query=email` | Check data breach |
| GET | `/api/security/ipinfo?query=IP` | IP geolocation |
| GET | `/api/security/shodan?query=IP` | Shodan host lookup |
| GET | `/api/security/securitytrails?query=domain` | DNS intelligence |
| GET | `/api/security/whois?query=domain` | WHOIS lookup |
| GET | `/api/security/greynoise?query=IP` | Threat intelligence |
| GET | `/api/security/urlscan?query=URL` | Website scan |
| GET | `/api/security/hunter?query=domain` | Email finder |
| GET | `/api/security/builtwith?query=domain` | Tech detection |
| GET | `/api/security/censys?query=IP` | Host intelligence |
| GET | `/api/security/openphish?query=URL` | Phishing check |
| GET | `/api/security/otx?query=IP` | OTX threat intel |
| GET | `/api/security/nvd?query=CVE-ID` | CVE lookup |
| GET | `/api/security/ipapi?query=IP` | IP geolocation |
| GET | `/api/security/emailrep?query=email` | Email reputation |
| GET | `/api/security/dns?query=domain` | DNS records |
| GET | `/api/security/safebrowsing?query=URL` | Safe browsing check |
| GET | `/api/security/cvedetails?query=CVE-ID` | CVE details |
| GET | `/api/security/tools` | List all tools |

### Activity Routes (`/api/activity`) — All require JWT

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/activity/log` | Log user action |
| GET | `/api/activity/my` | Get user activities |
| GET | `/api/activity/stats` | Get usage stats |
| DELETE | `/api/activity/clear` | Clear activity log |

---

## Database Collections

### `users`
```json
{
  "_id": "ObjectId",
  "name": "John Doe",
  "email": "john@example.com",
  "password": "$2a$12$hashed...",
  "registration_date": "2024-01-01T00:00:00Z"
}
```

### `activities`
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "tool_id": 2,
  "tool_name": "VirusTotal",
  "action_type": "test",
  "query_input": "example.com",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### `securitytools`
```json
{
  "_id": "ObjectId",
  "name": "AbuseIPDB",
  "category": "IP Intelligence",
  "description": "Malicious IP detection",
  "api_link": "https://www.abuseipdb.com",
  "tags": ["ip", "malicious", "abuse"]
}
```

---

## Testing with Postman

1. **Register:** `POST /api/auth/register` → body: `{name, email, password}`
2. **Login:** `POST /api/auth/login` → get JWT token
3. **Set Header:** `Authorization: Bearer <token>`
4. **Test API:** `GET /api/security/ipapi?query=8.8.8.8`

---

## Group Members

| Role | Responsibility |
|---|---|
| Full Stack Dev | Backend API + MongoDB |
| Frontend Dev | UI/UX Dashboard |
| Security Analyst | API Research + Integration |
| Database Admin | MongoDB Schema + Queries |

---

*CyberShield — Cyber Security API Intelligence Dashboard | Final Semester eProject | Group A*
