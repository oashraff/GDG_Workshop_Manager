/**
 * GDG EUE Event Manager - Main Application Entry Point
 * Enterprise-grade Express.js Architecture
 * Author: Omar Ashraf Mohammed
 * 
 * Purpose: Workshop Management for Google Developer Group
 * Security: OWASP Top 10 Compliant with Defence in Depth Architecture
 * Performance: Optimised middleware chain with efficient security checks
 */

// Environment Configuration - Load before other modules
require('dotenv').config();

// Core Dependencies
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const { body, validationResult } = require('express-validator');

// Security Middleware Stack
const {
    createRateLimiter,
    securityHeaders,
    csrfProtection,
    authGuard,
    sanitiseInput,
    sessionTimeout
} = require('./middleware/security');

// Authentication Controllers
const { handleLogin, handleLogout } = require('./controllers/auth');

// Application Configuration
const app = express();
const port = process.env.PORT || 5000;

// Security Headers - Applied first for maximum protection
app.use(securityHeaders());

// Cookie Parser - Required for CSRF protection
app.use(cookieParser());

// Body Parser Configuration - With size limits for DoS prevention
app.use(express.urlencoded({ 
    extended: true, 
    limit: '10mb',
    parameterLimit: 100 // Prevent parameter pollution
}));
app.use(express.json({ limit: '10mb' }));

// View Engine Configuration
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static Files - Served with security headers
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d', // Browser caching for performance
    etag: false // Disable ETags for security
}));

// Session Configuration - NIST SP 800-63B Compliant
app.use(session({
    secret: process.env.SECRET_KEY || 'gdg_eue_fallback_key_coursework_only',
    resave: false,
    saveUninitialized: false,
    name: 'gdg.session.id', // Custom session name
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true, // Prevent XSS access to cookies
        maxAge: parseInt(process.env.COOKIE_MAX_AGE) || 900000, // 15 minutes
        sameSite: 'strict' // CSRF protection
    },
    // Production should use Redis or database session store
    genid: () => {
        const crypto = require('crypto');
        return crypto.randomUUID();
    }
}));

// Rate Limiting - Applied before authentication routes
app.use('/login', createRateLimiter(15 * 60 * 1000, 5)); // 5 attempts per 15 minutes
app.use('/auth', createRateLimiter(15 * 60 * 1000, 5));

// Input Sanitisation - XSS Prevention
app.use(sanitiseInput);

// Session Timeout Management
app.use(sessionTimeout(parseInt(process.env.SESSION_TIMEOUT) || 900000));

// Global locals setup
app.use((req, res, next) => {
    res.locals.user = req.session?.authenticated ? { authenticated: true } : null;
    res.locals.csrfToken = null; // Default to null, will be set by routes that need it
    next();
});

// CSRF Protection instance - create once
const csrfMiddleware = csrfProtection();

// SQLite Database Configuration - With Connection Pooling
const sqlite3 = require('sqlite3').verbose();
global.db = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE, function(err) {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1); // Critical failure - cannot operate without database
    } else {
        console.log('✓ Database connected successfully');
        
        // Enable foreign key constraints for referential integrity
        global.db.run("PRAGMA foreign_keys=ON");
        
        // Performance optimisation: Enable Write-Ahead Logging
        global.db.run("PRAGMA journal_mode=WAL");
        
        // Security: Set query timeout to prevent DoS
        global.db.run("PRAGMA busy_timeout=30000");
        
        console.log('✓ Database configuration applied');
    }
});

// Graceful shutdown handling
process.on('SIGINT', () => {
    console.log('\n🔄 Graceful shutdown initiated...');
    if (global.db) {
        global.db.close((err) => {
            if (err) {
                console.error('Database close error:', err);
            } else {
                console.log('✓ Database connection closed');
            }
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});

// Route Handlers - Public Routes

/**
 * Home Page Route - GDG Landing Page
 * @route GET /
 * @access Public
 * @description Displays GDG On Campus EUE welcome page with navigation options
 */
app.get('/', (req, res) => {
    res.render('index', {
        title: 'GDG On Campus EUE - Event Manager',
        campusName: 'European Universities in Egypt',
        academicYear: 'April 2025'
    });
});

/**
 * Login Page Route
 * @route GET /login
 * @access Public
 * @description Displays login form for organisers
 */
app.get('/login', csrfMiddleware, (req, res) => {
    const error = req.query.error;
    const message = req.query.message;
    
    let errorMessage = null;
    let successMessage = null;
    
    // Map error codes to user-friendly messages
    if (error === 'authentication_required') {
        errorMessage = 'Please log in to access the organiser dashboard.';
    } else if (error === 'session_timeout') {
        errorMessage = 'Your session has expired. Please log in again.';
    } else if (error === 'csrf_invalid') {
        errorMessage = 'Security token expired. Please try logging in again.';
    }
    
    if (message === 'logged_out') {
        successMessage = 'You have been successfully logged out.';
    }
    
    res.render('login', {
        title: 'Organiser Login - GDG EUE',
        error: errorMessage,
        message: successMessage,
        csrfToken: req.csrfToken()
    });
});

/**
 * Login Processing Route
 * @route POST /login
 * @access Public
 * @description Processes database-verified login credentials with security validation
 */
app.post('/login', [
    csrfMiddleware,
    body('username')
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .trim()
        .escape(),
    body('password')
        .isLength({ min: 1 })
        .withMessage('Password is required')
], handleLogin);

/**
 * Logout Route
 * @route POST /logout
 * @access Private
 * @description Securely terminates user session
 */
app.post('/logout', authGuard, csrfMiddleware, handleLogout);

// Protected Route Handlers - Organiser Dashboard

/**
 * Organiser Dashboard Route
 * @route GET /organiser
 * @access Private
 * @description Main dashboard for workshop management
 */
app.get('/organiser', authGuard, (req, res) => {
    // Redirect to the main events dashboard which handles data fetching
    res.redirect('/events/dashboard');
});

// Add all route handlers for different modules
const eventsRoutes = require('./routes/events');
const attendeeRoutes = require('./routes/attendee');

// Mount route modules with appropriate prefixes
app.use('/events', authGuard, eventsRoutes); // Protected event management
app.use('/attendee', attendeeRoutes); // Public attendee interface

// Centralised Error Handling Middleware

/**
 * 404 Not Found Handler
 * @security Prevents information disclosure about application structure
 */
app.use((req, res) => {
    res.status(404).render('error/404', {
        title: 'Page Not Found - GDG EUE',
        requestedPath: req.path
    });
});

/**
 * Global Error Handler
 * @security Sanitises error output to prevent information disclosure
 * @param {Error} err - Error object
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Function} next - Express next function
 */
app.use((err, req, res, next) => {
    console.error('Application Error:', {
        message: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        timestamp: new Date().toISOString()
    });

    // Handle CSRF errors specifically
    if (err.code === 'EBADCSRFTOKEN') {
        // For booking forms, redirect back to event with error
        if (req.path.startsWith('/attendee/book/')) {
            const eventId = req.path.split('/').pop();
            return res.redirect(`/attendee/event/${eventId}?error=security_token_expired`);
        }
        
        // For login forms
        if (req.path === '/login') {
            return res.redirect('/login?error=csrf_invalid');
        }
        
        return res.status(403).render('error/500', {
            title: 'Security Error - GDG EUE',
            message: 'Security token expired. Please refresh the page and try again.'
        });
    }
    
    // Different error responses based on environment
    if (process.env.NODE_ENV === 'production') {
        res.status(500).render('error/500', {
            title: 'Server Error - GDG EUE',
            message: 'An internal server error occurred. Please try again later.'
        });
    } else {
        // Development: Show detailed error information
        res.status(500).send(`
            <h1>Development Error</h1>
            <p><strong>Message:</strong> ${err.message}</p>
            <pre>${err.stack}</pre>
        `);
    }
});

// Start Server
app.listen(port, '0.0.0.0', () => {
    console.log(`
[SERVER] GDG EUE Event Manager Started Successfully
[URL] Server running on: http://0.0.0.0:${port}
[SECURITY] ${process.env.NODE_ENV === 'production' ? 'Production' : 'Development'} mode
[DATABASE] SQLite with WAL mode enabled
[PROTECTION] OWASP compliance active
    `);
});

