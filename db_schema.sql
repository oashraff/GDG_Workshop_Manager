-- GDG EUE Event Manager Database Schema
-- Normalised to 3NF with integrity constraints
-- Author: Omar Ashraf Mohammed
-- Purpose: Workshop Management for Google Developer Group

-- Security: Enable foreign key constraints to maintain referential integrity
-- Performance: B-tree indexing provides O(log n) lookup complexity
PRAGMA foreign_keys=ON;

BEGIN TRANSACTION;

-- Core Events Table - Primary entity for GDG workshops
-- Design rationale: Centralised event storage with JSON fields for flexible tech stack management
CREATE TABLE IF NOT EXISTS gdg_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL CHECK(length(title) >= 5 AND length(title) <= 200),
    description TEXT,
    tech_stack TEXT DEFAULT '[]', -- JSON array: ['Firebase', 'Flutter', 'Android']
    skill_level INTEGER CHECK(skill_level BETWEEN 1 AND 3), -- 1=Beginner, 2=Intermediate, 3=Advanced
    is_recurring BOOLEAN DEFAULT 0,
    co_hosts TEXT DEFAULT '[]', -- JSON array: ['member@uol.eue.edu.eg']
    max_attendees INTEGER DEFAULT 50 CHECK(max_attendees > 0),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    published_at DATETIME NULL, -- NULL indicates draft status
    last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_date DATETIME NOT NULL,
    duration_minutes INTEGER DEFAULT 90 CHECK(duration_minutes > 0)
);

-- Ticket Types - Supports GDG member pricing and standard tickets
-- Business Rule: GDG members receive 100% discount for educational workshops
CREATE TABLE IF NOT EXISTS ticket_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    name TEXT NOT NULL, -- 'GDG Member (Free)', 'Standard'
    price DECIMAL(10,2) DEFAULT 0.00 CHECK(price >= 0),
    quantity_available INTEGER NOT NULL CHECK(quantity_available >= 0),
    gdg_discount DECIMAL(3,2) DEFAULT 0.00 CHECK(gdg_discount BETWEEN 0 AND 1),
    is_member_only BOOLEAN DEFAULT 0,
    FOREIGN KEY (event_id) REFERENCES gdg_events(id) ON DELETE CASCADE
);

-- Bookings - Records attendee registrations with GDG member verification
-- Security: Stores member ID for verification against @uol.eue.edu.eg domain
CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    ticket_type_id INTEGER NOT NULL,
    attendee_name TEXT NOT NULL CHECK(length(attendee_name) >= 2),
    attendee_email TEXT NOT NULL,
    gdg_member_id TEXT, -- @uol.eue.edu.eg email for member verification
    booking_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    booking_status TEXT DEFAULT 'confirmed' CHECK(booking_status IN ('confirmed', 'waitlist', 'cancelled')),
    FOREIGN KEY (event_id) REFERENCES gdg_events(id) ON DELETE CASCADE,
    FOREIGN KEY (ticket_type_id) REFERENCES ticket_types(id) ON DELETE CASCADE
);

-- Authentication Sessions - Secure session management for organisers
-- Security: Session tokens with configurable timeout for OWASP compliance
CREATE TABLE IF NOT EXISTS admin_sessions (
    session_id TEXT PRIMARY KEY,
    session_data TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Admin Users Table - Database-stored credentials with role-based access
-- Security: bcrypt hashed passwords with NIST SP 800-63B compliance
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3),
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'organiser' CHECK(role IN ('organiser', 'admin', 'co_host')),
    email TEXT UNIQUE,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME
);

-- Performance Optimisation: Create indices for frequent query patterns
-- Complexity Analysis: B-tree indices reduce lookup from O(n) to O(log n)
CREATE INDEX IF NOT EXISTS idx_events_published ON gdg_events(published_at);
CREATE INDEX IF NOT EXISTS idx_events_date ON gdg_events(event_date);
CREATE INDEX IF NOT EXISTS idx_bookings_event ON bookings(event_id);
CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings(booking_status);
CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS idx_admin_email ON admin_users(email);
CREATE INDEX IF NOT EXISTS idx_admin_active ON admin_users(is_active);

-- Sample Data for GDG EUE Workshop Demonstrations

INSERT INTO gdg_events (title, description, tech_stack, skill_level, event_date, duration_minutes, published_at) VALUES 
('Firebase Authentication Masterclass', 'Learn to implement secure user authentication with Firebase Auth, covering OAuth, email verification, and security best practices for modern web applications.', '["Firebase", "JavaScript", "Security"]', 2, '2025-07-15 14:00:00', 120, CURRENT_TIMESTAMP),
('Flutter Mobile Development Workshop', 'Build your first cross-platform mobile application using Flutter framework, covering widgets, state management, and API integration.', '["Flutter", "Dart", "Mobile"]', 1, '2025-07-20 10:00:00', 180, CURRENT_TIMESTAMP),
('Advanced Android with Kotlin', 'Deep dive into modern Android development with Kotlin, exploring coroutines, architecture patterns, and Material Design 3.', '["Android", "Kotlin", "Architecture"]', 3, '2025-07-25 13:00:00', 150, CURRENT_TIMESTAMP);

-- Draft workshop for testing unpublished content
INSERT INTO gdg_events (title, description, tech_stack, skill_level, event_date, duration_minutes) VALUES 
('Google Cloud Functions Deep Dive', 'Serverless computing with Google Cloud Functions, covering deployment strategies, monitoring, and cost optimisation techniques.', '["Google Cloud", "Node.js", "Serverless"]', 2, '2025-08-01 15:00:00', 90);

-- Ticket types for workshops - demonstrating GDG member benefits
INSERT INTO ticket_types (event_id, name, price, quantity_available, gdg_discount, is_member_only) VALUES 
(1, 'GDG Member (Free)', 0.00, 30, 1.00, 1),
(1, 'Standard', 25.00, 20, 0.00, 0),
(2, 'GDG Member (Free)', 0.00, 25, 1.00, 1),
(2, 'Standard', 30.00, 15, 0.00, 0),
(3, 'GDG Member (Free)', 0.00, 20, 1.00, 1),
(3, 'Standard', 40.00, 10, 0.00, 0);

-- Sample bookings for demonstration
INSERT INTO bookings (event_id, ticket_type_id, attendee_name, attendee_email, gdg_member_id) VALUES 
(1, 1, 'Sarah Mitchell', 'sarah.mitchell@uol.eue.edu.eg', 'sarah.mitchell@uol.eue.edu.eg'),
(1, 2, 'James Wilson', 'james.wilson@gmail.com', NULL),
(2, 1, 'Ahmed Hassan', 'ahmed.hassan@uol.eue.edu.eg', 'ahmed.hassan@uol.eue.edu.eg');

-- Insert default admin user with hashed 'gdgadmin2025' as the password
-- Security: Using same bcrypt hash from environment for consistency
INSERT INTO admin_users (username, password_hash, role, email, is_active) VALUES 
('admin', '$2b$12$lNhlg.g96O7glCgpnPRkhO9hhvN384/NBlW5JiCrnMXkuTlDiA8gm', 'admin', 'admin@gdg.eue.edu.eg', 1);

COMMIT;

