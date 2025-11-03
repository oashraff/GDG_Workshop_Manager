# GDG On Campus EUE Event Manager

Live URL: https://gdgmanager.koyeb.app/
A comprehensive event management system designed specifically for Google Developer Group (GDG) On Campus at European Universities in Egypt (EUE). This application enables organisers to create, manage, and publish tech workshops while providing attendees with an intuitive booking experience.

**Author**: Omar Ashraf Mohammed  

## Project Overview

### Purpose
This event management system serves as a workshop management platform for GDG On Campus EUE, facilitating the organisation and booking of technology workshops, seminars, and hands-on learning experiences focused on Google technologies including Firebase, Flutter, Android development, and more.

### Key Features
- **Organiser Dashboard**: Complete workshop lifecycle management
- **Public Event Discovery**: Attendee-friendly workshop browsing and filtering
- **Secure Booking System**: GDG member verification and booking management
- **Advanced Security**: OWASP Top 10 compliant with comprehensive protection measures
- **Responsive Design**: Google Material Design 3 implementation
- **Accessibility**: WCAG 2.1 AA compliant interface

## Technical Architecture

### Technology Stack
- **Backend**: Node.js with Express.js 4.x
- **Database**: SQLite3 5.x with optimised schema design
- **Templating**: EJS 3.x for server-side rendering
- **Security**: Multi-layered approach with industry-standard practices
- **Styling**: Custom CSS implementing Google Material Design principles

### Security Implementation
```
┌─────────────────────────────────────────────────────────────┐
│                    Security Architecture                     │
├─────────────────────────────────────────────────────────────┤
│ 1. Helmet.js         → Security Headers & CSP              │
│ 2. CSRF Protection   → Synchroniser Token Pattern          │
│ 3. Rate Limiting     → Brute Force Prevention              │
│ 4. Session Security  → HTTP-only, Secure, SameSite        │
│ 5. Input Validation  → Express-validator chains            │
│ 6. SQL Injection     → Parameterised queries              │
│ 7. XSS Prevention    → Output encoding & sanitisation     │
│ 8. Authentication    → bcrypt with cost factor 12         │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start Guide

### Prerequisites
- **Node.js**: Version 16.0.0 or higher
- **npm**: Version 8.0.0 or higher
- **SQLite3**: Included with package dependencies

### Installation & Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Database Initialisation**
   ```bash
   npm run build-db
   ```

3. **Start Application**
   ```bash
   npm run start
   ```

4. **Access Application**
   - **Public Interface**: http://localhost:3000/attendee
   - **Organiser Dashboard**: http://localhost:3000/organiser 
      - **Default Admin Credentials**:
         - Username: `admin`
         - Password: `gdg2025admin`
   - **Home Page**: http://localhost:3000

### Default Configuration
- **Port**: 3000
- **Environment**: Development
- **Session Timeout**: 15 minutes
- **Database**: SQLite with sample data included in db

### Additional Functionality Libraries
Beyond the original template dependencies (`express`, `sqlite3`, `ejs`), the following libraries were integrated:

- **`bcrypt`** (^5.1.1) - NIST SP 800-63B compliant password hashing with cost factor 12
- **`helmet`** (^7.1.0) - Comprehensive security headers and Content Security Policy implementation
- **`csurf`** (^1.11.0) - CSRF protection using synchroniser token pattern
- **`express-rate-limit`** (^7.1.5) - Brute force protection with configurable attempt thresholds
- **`express-session`** (^1.17.3) - Secure session management with HTTP-only cookies
- **`express-validator`** (^7.0.1) - Server-side input validation and sanitisation chains
- **`cookie-parser`** (^1.4.7) - Cookie parsing middleware required for CSRF protection
- **`dotenv`** (^16.3.1) - Environment variable management for secure configuration
- **`date-fns`** (^2.30.0) - Workshop date formatting and manipulation utilities
- **`axios`** (^1.6.2) - HTTP client for potential Google API integration features

## Available Scripts

| Command | Description | Usage |
|---------|-------------|--------|
| `npm start` | Start production server | Primary deployment command |
| `npm run build-db` | Initialise database from schema | First-time setup & reset |
| `npm run clean-db` | Remove existing database | Development cleanup |

## Security Features

### Authentication System
- **Password Hashing**: bcrypt with cost factor 12 (NIST SP 800-63B compliant)
- **Session Management**: Secure HTTP-only cookies with SameSite protection
- **Brute Force Protection**: 5 attempts per 15-minute window
- **Session Timeout**: Automatic logout after 15 minutes of inactivity

### Data Protection
- **CSRF Protection**: Synchronizer token pattern implementation
- **SQL Injection Prevention**: Parameterised queries throughout
- **XSS Protection**: Input sanitisation and output encoding
- **Headers Security**: Comprehensive security headers via Helmet.js


### Implementation

- **Security Architecture**: Implementation of NIST cybersecurity guidelines
- **Algorithm Analysis**: Optimised database operations
- **Design Patterns**: MVC architecture with service layer separation
- **Code Documentation**: Comprehensive JSDoc documentation


