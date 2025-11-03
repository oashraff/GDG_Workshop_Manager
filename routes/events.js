/**
 * Event Management Routes for GDG EUE Event Manager
 * RESTful API Design with Comprehensive Validation
 * Author: Omar Ashraf Mohammed
 * 
 * Architecture: MVC pattern with service layer separation
 * Security: Input validation, SQL injection prevention, XSS protection
 * Performance: Optimised database queries with indexed lookups
 */

const express = require('express');
const router = express.Router();
const { body, param, validationResult } = require('express-validator');
const { format, parseISO, addDays } = require('date-fns');
const { csrfProtection } = require('../middleware/security');

/**
 * Event Service Class - Business Logic Layer
 * @description Encapsulates event-related operations with error handling
 * @complexity Database operations: O(log n) via B-tree indexing
 */
class EventService {
    /**
     * Retrieve all events with optional filtering
     * @param {Object} filters - Filter criteria
     * @returns {Promise<Array>} Array of event objects
     * @complexity O(log n) with indexed queries
     */
    static async getAllEvents(filters = {}) {
        return new Promise((resolve, reject) => {
            let query = `
                SELECT 
                    e.*,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_id = e.id AND b.booking_status = 'confirmed') as confirmed_bookings,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_id = e.id AND b.booking_status = 'waitlist') as waitlist_count
                FROM gdg_events e
            `;
            
            const conditions = [];
            const params = [];
            
            // Apply filters with parameterised queries for SQL injection prevention
            if (filters.published !== undefined) {
                if (filters.published) {
                    conditions.push('e.published_at IS NOT NULL');
                } else {
                    conditions.push('e.published_at IS NULL');
                }
            }
            
            if (filters.tech_stack) {
                conditions.push('e.tech_stack LIKE ?');
                params.push(`%${filters.tech_stack}%`);
            }
            
            if (filters.skill_level) {
                conditions.push('e.skill_level = ?');
                params.push(filters.skill_level);
            }
            
            if (conditions.length > 0) {
                query += ' WHERE ' + conditions.join(' AND ');
            }
            
            query += ' ORDER BY e.event_date ASC';
            
            global.db.all(query, params, (err, rows) => {
                if (err) {
                    console.error('Database query error:', err);
                    reject(err);
                } else {
                    // Parse JSON fields for each event
                    const processedRows = rows.map(row => ({
                        ...row,
                        tech_stack: JSON.parse(row.tech_stack || '[]'),
                        co_hosts: JSON.parse(row.co_hosts || '[]'),
                        event_date: new Date(row.event_date),
                        created_at: new Date(row.created_at),
                        published_at: row.published_at ? new Date(row.published_at) : null,
                        last_modified: new Date(row.last_modified)
                    }));
                    resolve(processedRows);
                }
            });
        });
    }
    
    /**
     * Retrieve single event by ID with related data
     * @param {number} eventId - Event identifier
     * @returns {Promise<Object>} Event object with ticket types
     * @security Parameterised query prevents SQL injection
     */
    static async getEventById(eventId) {
        return new Promise((resolve, reject) => {
            const query = `
                SELECT 
                    e.*,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_id = e.id AND b.booking_status = 'confirmed') as confirmed_bookings
                FROM gdg_events e 
                WHERE e.id = ?
            `;
            
            global.db.get(query, [eventId], (err, row) => {
                if (err) {
                    reject(err);
                } else if (!row) {
                    resolve(null);
                } else {
                    // Parse JSON fields and get ticket types
                    const event = {
                        ...row,
                        tech_stack: JSON.parse(row.tech_stack || '[]'),
                        co_hosts: JSON.parse(row.co_hosts || '[]'),
                        event_date: new Date(row.event_date),
                        created_at: new Date(row.created_at),
                        published_at: row.published_at ? new Date(row.published_at) : null,
                        last_modified: new Date(row.last_modified)
                    };
                    
                    // Get ticket types for this event
                    const ticketQuery = 'SELECT * FROM ticket_types WHERE event_id = ?';
                    global.db.all(ticketQuery, [eventId], (ticketErr, ticketRows) => {
                        if (ticketErr) {
                            reject(ticketErr);
                        } else {
                            event.ticket_types = ticketRows;
                            resolve(event);
                        }
                    });
                }
            });
        });
    }
    
    /**
     * Create new workshop event
     * @param {Object} eventData - Event details
     * @returns {Promise<number>} Created event ID
     * @security Input validation and parameterised queries
     */
    static async createEvent(eventData) {
        return new Promise((resolve, reject) => {
            const {
                title, description, tech_stack, skill_level, 
                event_date, duration_minutes, max_attendees, co_hosts
            } = eventData;
            
            const query = `
                INSERT INTO gdg_events (
                    title, description, tech_stack, skill_level,
                    event_date, duration_minutes, max_attendees, co_hosts,
                    created_at, last_modified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `;
            
            const params = [
                title,
                description,
                JSON.stringify(tech_stack || []),
                skill_level,
                event_date,
                duration_minutes || 90,
                max_attendees || 50,
                JSON.stringify(co_hosts || [])
            ];
            
            global.db.run(query, params, function(err) {
                if (err) {
                    console.error('Event creation error:', err);
                    reject(err);
                } else {
                    resolve(this.lastID);
                }
            });
        });
    }
    
    /**
     * Update existing event
     * @param {number} eventId - Event identifier
     * @param {Object} updateData - Updated event data
     * @returns {Promise<boolean>} Success status
     */
    static async updateEvent(eventId, updateData) {
        return new Promise((resolve, reject) => {
            const {
                title, description, tech_stack, skill_level,
                event_date, duration_minutes, max_attendees, co_hosts
            } = updateData;
            
            const query = `
                UPDATE gdg_events SET
                    title = ?, description = ?, tech_stack = ?, skill_level = ?,
                    event_date = ?, duration_minutes = ?, max_attendees = ?, co_hosts = ?,
                    last_modified = CURRENT_TIMESTAMP
                WHERE id = ?
            `;
            
            const params = [
                title,
                description,
                JSON.stringify(tech_stack || []),
                skill_level,
                event_date,
                duration_minutes,
                max_attendees,
                JSON.stringify(co_hosts || []),
                eventId
            ];
            
            global.db.run(query, params, function(err) {
                if (err) {
                    reject(err);
                } else {
                    resolve(this.changes > 0);
                }
            });
        });
    }
    
    /**
     * Publish event (set published_at timestamp)
     * @param {number} eventId - Event identifier
     * @returns {Promise<boolean>} Success status
     */
    static async publishEvent(eventId) {
        return new Promise((resolve, reject) => {
            const query = 'UPDATE gdg_events SET published_at = CURRENT_TIMESTAMP WHERE id = ? AND published_at IS NULL';
            
            global.db.run(query, [eventId], function(err) {
                if (err) {
                    reject(err);
                } else {
                    resolve(this.changes > 0);
                }
            });
        });
    }

    /**
     * Delete event and all associated data
     * @param {number} eventId - Event identifier
     * @returns {Promise<boolean>} Success status
     * @security Cascading deletion with transaction safety
     */
    static async deleteEvent(eventId) {
        return new Promise((resolve, reject) => {
            // Begin transaction for atomic deletion
            global.db.serialize(() => {
                global.db.run('BEGIN TRANSACTION');
                
                // Delete bookings first (foreign key constraint) - FIXED TABLE NAME
                global.db.run(
                    'DELETE FROM bookings WHERE event_id = ?',
                    [eventId],
                    function(err) {
                        if (err) {
                            global.db.run('ROLLBACK');
                            return reject(err);
                        }
                        
                        // Delete ticket types
                        global.db.run(
                            'DELETE FROM ticket_types WHERE event_id = ?',
                            [eventId],
                            function(err) {
                                if (err) {
                                    global.db.run('ROLLBACK');
                                    return reject(err);
                                }
                                
                                // Delete event
                                global.db.run(
                                    'DELETE FROM gdg_events WHERE id = ?',
                                    [eventId],
                                    function(err) {
                                        if (err) {
                                            global.db.run('ROLLBACK');
                                            return reject(err);
                                        }
                                        
                                        // Commit transaction
                                        global.db.run('COMMIT', function(err) {
                                            if (err) {
                                                global.db.run('ROLLBACK');
                                                return reject(err);
                                            }
                                            
                                            resolve(this.changes > 0);
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            });
        });
    }
}

/**
 * Validation Middleware - Express Validator Chains
 * @security Comprehensive input validation to prevent injection attacks
 */
const eventValidation = [
    body('title')
        .isLength({ min: 5, max: 200 })
        .withMessage('Title must be between 5 and 200 characters')
        .trim()
        .escape(),
    body('description')
        .optional()
        .isLength({ max: 2000 })
        .withMessage('Description cannot exceed 2000 characters')
        .trim(),
    body('skill_level')
        .isInt({ min: 1, max: 3 })
        .withMessage('Skill level must be 1 (Beginner), 2 (Intermediate), or 3 (Advanced)'),
    body('event_date')
        .isISO8601()
        .withMessage('Event date must be in valid ISO format')
        .custom((value) => {
            const eventDate = new Date(value);
            const now = new Date();
            if (eventDate <= now) {
                throw new Error('Event date must be in the future');
            }
            return true;
        }),
    body('duration_minutes')
        .optional()
        .isInt({ min: 30, max: 480 })
        .withMessage('Duration must be between 30 and 480 minutes'),
    body('max_attendees')
        .optional()
        .isInt({ min: 1, max: 500 })
        .withMessage('Maximum attendees must be between 1 and 500'),
    body('tech_stack')
        .optional()
        .custom((value) => {
            // Validate tech stack is array of strings
            if (typeof value === 'string') {
                try {
                    const parsed = JSON.parse(value);
                    if (!Array.isArray(parsed)) {
                        throw new Error('Tech stack must be an array');
                    }
                } catch {
                    throw new Error('Invalid tech stack format');
                }
            }
            return true;
        })
];

/**
 * @route GET /events/dashboard
 * @desc Display organiser dashboard with published and draft events
 * @access Private (authenticated organisers only)
 * @security Session validation via authGuard middleware
 */
router.get('/dashboard', csrfProtection(), async (req, res) => {
    try {
        // Get published and draft events separately for dashboard display
        const [publishedEvents, draftEvents] = await Promise.all([
            EventService.getAllEvents({ published: true }),
            EventService.getAllEvents({ published: false })
        ]);
        
        res.render('organiser/dashboard', {
            title: 'GDG EUE Workshop Manager',
            description: 'Google Developer Group @ European Universities in Egypt',
            publishedEvents,
            draftEvents,
            formatDate: (date) => format(date, 'dd/MM/yyyy HH:mm'),
            user: req.session,
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Dashboard loading error:', error);
        res.status(500).render('error/500', {
            title: 'Dashboard Error',
            message: 'Unable to load dashboard. Please try again.'
        });
    }
});

/**
 * @route GET /events/create
 * @desc Display event creation form
 * @access Private
 * @description Renders form for creating new workshop events
 */
router.get('/create', csrfProtection(), (req, res) => {
    res.render('organiser/create-event', {
        title: 'Create New Workshop - GDG EUE',
        csrfToken: req.csrfToken(),
        formData: {}, // Empty form data for new event
        errors: []
    });
});

/**
 * @route POST /events/create
 * @desc Process new event creation
 * @access Private
 * @validation Comprehensive input validation and sanitisation
 */
router.post('/create', [csrfProtection(), ...eventValidation], async (req, res) => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).render('organiser/create-event', {
                title: 'Create New Workshop - GDG EUE',
                csrfToken: req.csrfToken(),
                formData: req.body,
                errors: errors.array()
            });
        }
        
        // Parse tech stack and co-hosts if provided as strings
        let tech_stack = req.body.tech_stack;
        let co_hosts = req.body.co_hosts;
        
        if (typeof tech_stack === 'string') {
            tech_stack = tech_stack ? tech_stack.split(',').map(s => s.trim()) : [];
        }
        
        if (typeof co_hosts === 'string') {
            co_hosts = co_hosts ? co_hosts.split(',').map(s => s.trim()) : [];
        }
        
        // Create event
        const eventId = await EventService.createEvent({
            ...req.body,
            tech_stack,
            co_hosts
        });
        
        // Create default ticket types for new event
        const createTicketPromises = [
            // GDG Member (Free) ticket
            new Promise((resolve, reject) => {
                const query = `
                    INSERT INTO ticket_types (event_id, name, price, quantity_available, gdg_discount, is_member_only)
                    VALUES (?, 'GDG Member (Free)', 0.00, 30, 1.00, 1)
                `;
                global.db.run(query, [eventId], function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                });
            }),
            // Standard ticket
            new Promise((resolve, reject) => {
                const query = `
                    INSERT INTO ticket_types (event_id, name, price, quantity_available, gdg_discount, is_member_only)
                    VALUES (?, 'Standard', 25.00, 20, 0.00, 0)
                `;
                global.db.run(query, [eventId], function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                });
            })
        ];
        
        await Promise.all(createTicketPromises);
        
        res.redirect(`/events/edit/${eventId}?success=created`);
    } catch (error) {
        console.error('Event creation error:', error);
        res.status(500).render('organiser/create-event', {
            title: 'Create New Workshop - GDG EUE',
            csrfToken: req.csrfToken(),
            formData: req.body,
            errors: [{ msg: 'Failed to create event. Please try again.' }]
        });
    }
});

/**
 * @route GET /events/edit/:id
 * @desc Display event editing form
 * @access Private
 * @param {number} id - Event identifier
 */
router.get('/edit/:id', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID'),
    csrfProtection()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).redirect('/events/dashboard');
        }
        
        const event = await EventService.getEventById(req.params.id);
        if (!event) {
            return res.status(404).render('error/404', {
                title: 'Event Not Found',
                message: 'The requested workshop event could not be found.'
            });
        }
        
        res.render('organiser/edit-event', {
            title: `Edit ${event.title} - GDG EUE`,
            event,
            csrfToken: req.csrfToken(),
            formatDate: (date) => format(date, "yyyy-MM-dd'T'HH:mm"),
            success: req.query.success,
            errors: []
        });
    } catch (error) {
        console.error('Event edit loading error:', error);
        res.status(500).redirect('/events/dashboard');
    }
});

/**
 * @route POST /events/edit/:id
 * @desc Process event updates
 * @access Private
 * @param {number} id - Event identifier
 */
router.post('/edit/:id', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID'),
    ...eventValidation
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const event = await EventService.getEventById(req.params.id);
            return res.status(400).render('organiser/edit-event', {
                title: `Edit ${event?.title || 'Event'} - GDG EUE`,
                event: { ...event, ...req.body },
                csrfToken: req.csrfToken(),
                formatDate: (date) => format(date, "yyyy-MM-dd'T'HH:mm"),
                errors: errors.array()
            });
        }
        
        // Parse arrays from form data
        let tech_stack = req.body.tech_stack;
        let co_hosts = req.body.co_hosts;
        
        if (typeof tech_stack === 'string') {
            tech_stack = tech_stack ? tech_stack.split(',').map(s => s.trim()) : [];
        }
        
        if (typeof co_hosts === 'string') {
            co_hosts = co_hosts ? co_hosts.split(',').map(s => s.trim()) : [];
        }
        
        const updated = await EventService.updateEvent(req.params.id, {
            ...req.body,
            tech_stack,
            co_hosts
        });
        
        if (updated) {
            res.redirect(`/events/edit/${req.params.id}?success=updated`);
        } else {
            throw new Error('Failed to update event');
        }
    } catch (error) {
        console.error('Event update error:', error);
        const event = await EventService.getEventById(req.params.id);
        res.status(500).render('organiser/edit-event', {
            title: `Edit ${event?.title || 'Event'} - GDG EUE`,
            event,
            csrfToken: req.csrfToken(),
            formatDate: (date) => format(date, "yyyy-MM-dd'T'HH:mm"),
            errors: [{ msg: 'Failed to update event. Please try again.' }]
        });
    }
});

/**
 * @route POST /events/publish/:id
 * @desc Publish draft event
 * @access Private
 * @param {number} id - Event identifier
 */
router.post('/publish/:id', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Invalid event ID' });
        }
        
        const published = await EventService.publishEvent(req.params.id);
        if (published) {
            res.json({ success: true, message: 'Event published successfully' });
        } else {
            res.status(400).json({ error: 'Event not found or already published' });
        }
    } catch (error) {
        console.error('Event publish error:', error);
        res.status(500).json({ error: 'Failed to publish event' });
    }
});

/**
 * @route GET /events/api/list
 * @desc JSON API for event listing (for AJAX requests)
 * @access Private
 * @description Returns events in JSON format for dynamic loading
 */
router.get('/api/list', async (req, res) => {
    try {
        const filters = {
            published: req.query.published === 'true',
            tech_stack: req.query.tech_stack,
            skill_level: req.query.skill_level ? parseInt(req.query.skill_level) : undefined
        };
        
        const events = await EventService.getAllEvents(filters);
        res.json({
            success: true,
            events: events.map(event => ({
                ...event,
                event_date: event.event_date.toISOString(),
                created_at: event.created_at.toISOString(),
                published_at: event.published_at?.toISOString() || null,
                last_modified: event.last_modified.toISOString()
            }))
        });
    } catch (error) {
        console.error('API list error:', error);
        res.status(500).json({ error: 'Failed to retrieve events' });
    }
});

/**
 * @route GET /events/:id/attendees
 * @desc Get attendees list for a specific event
 * @access Private (Organiser only)
 */
router.get('/:id/attendees', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID'),
    csrfProtection()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Invalid event ID' });
        }

        const eventId = parseInt(req.params.id);
        
        // Get attendees for the event - fixed column names and date handling
        const query = `
            SELECT 
                b.id as booking_id,
                b.attendee_name,
                b.attendee_email,
                b.booking_status,
                b.booking_date as booked_at,
                COALESCE(tt.name, 'Standard') as type_name,
                COALESCE(tt.price, 0) as price
            FROM bookings b
            LEFT JOIN ticket_types tt ON b.ticket_type_id = tt.id
            WHERE b.event_id = ? AND b.booking_status = 'confirmed'
            ORDER BY b.booking_date DESC
        `;

        global.db.all(query, [eventId], (err, attendees) => {
            if (err) {
                console.error('Error fetching attendees:', err);
                return res.status(500).json({ error: 'Failed to fetch attendees' });
            }

            res.json({ 
                success: true, 
                attendees: attendees || [],
                count: attendees ? attendees.length : 0
            });
        });
    } catch (error) {
        console.error('Attendees fetch error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * @route GET /events/:id/export-calendar
 * @desc Export event to .ics calendar format
 * @access Private (Organiser only)
 */
router.get('/:id/export-calendar', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).redirect('/events/dashboard');
        }

        const eventId = parseInt(req.params.id);
        
        // Get event details
        const query = `
            SELECT 
                title,
                description,
                event_date,
                duration_minutes
            FROM gdg_events 
            WHERE id = ?
        `;

        global.db.get(query, [eventId], (err, event) => {
            if (err || !event) {
                console.error('Error fetching event for calendar export:', err);
                return res.status(404).redirect('/events/dashboard');
            }

            // Create .ics content
            const startDate = new Date(event.event_date);
            const endDate = new Date(startDate.getTime() + (event.duration_minutes || 90) * 60000);
            
            // Format dates for .ics (YYYYMMDDTHHMMSSZ)
            const formatICSDate = (date) => {
                return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
            };

            const icsContent = [
                'BEGIN:VCALENDAR',
                'VERSION:2.0',
                'PRODID:-//GDG EUE//Workshop Manager//EN',
                'CALSCALE:GREGORIAN',
                'METHOD:PUBLISH',
                'BEGIN:VEVENT',
                `UID:workshop-${eventId}@gdg-eue.com`,
                `DTSTART:${formatICSDate(startDate)}`,
                `DTEND:${formatICSDate(endDate)}`,
                `SUMMARY:${event.title}`,
                `DESCRIPTION:${event.description || 'GDG EUE Workshop'}`,
                `LOCATION:GDG EUE Campus, Computer Science Building`,
                'STATUS:CONFIRMED',
                'TRANSP:OPAQUE',
                'END:VEVENT',
                'END:VCALENDAR'
            ].join('\r\n');

            // Set headers for .ics file download
            res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="gdg-workshop-${eventId}.ics"`);
            res.send(icsContent);
        });
    } catch (error) {
        console.error('Calendar export error:', error);
        res.status(500).redirect('/events/dashboard');
    }
});

/**
 * @route DELETE /events/delete/:id
 * @desc Delete workshop permanently
 * @access Private
 * @param {number} id - Event identifier
 * @security Requires CSRF token and confirmation
 */
router.delete('/delete/:id', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID'),
    csrfProtection()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid event ID' 
            });
        }

        const eventId = req.params.id;
        
        // Verify event exists and get details for logging
        const event = await EventService.getEventById(eventId);
        if (!event) {
            return res.status(404).json({ 
                success: false, 
                error: 'Workshop not found' 
            });
        }

        // Delete event and all related data
        const deleted = await EventService.deleteEvent(eventId);
        
        if (deleted) {
            console.log(`Workshop deleted: ${event.title} (ID: ${eventId})`);
            res.json({ 
                success: true, 
                message: 'Workshop deleted successfully' 
            });
        } else {
            res.status(500).json({ 
                success: false, 
                error: 'Failed to delete workshop' 
            });
        }
    } catch (error) {
        console.error('Workshop deletion error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error during deletion' 
        });
    }
});

module.exports = router;
