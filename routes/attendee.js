/**
 * Attendee Interface Routes for GDG EUE Event Manager
 * Author: Omar Ashraf Mohammed
 * 
 * Purpose: Public routes for workshop discovery, filtering, and booking
 * Security: Input validation without authentication requirements
 * Complexity: O(log n) for event discovery with indexed queries
 */

const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const { format, parseISO, isAfter } = require('date-fns');
const { csrfProtection } = require('../middleware/security');

/**
 * Attendee Service Class - Public Event Operations
 * @description Handles public event discovery and booking functionality
 * @security All queries use parameterisation to prevent SQL injection
 */
class AttendeeService {
    /**
     * Get all published upcoming events with availability
     * @param {Object} filters - Search and filter criteria
     * @returns {Promise<Array>} Array of public event data
     * @complexity O(log n) with indexed queries on published_at and event_date
     */
    static async getUpcomingEvents(filters = {}) {
        return new Promise((resolve, reject) => {
            let query = `
                SELECT 
                    e.*,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_id = e.id AND b.booking_status = 'confirmed') as confirmed_bookings,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_id = e.id AND b.booking_status = 'waitlist') as waitlist_count,
                    (SELECT SUM(quantity_available) FROM ticket_types tt WHERE tt.event_id = e.id) as total_capacity
                FROM gdg_events e
                WHERE e.published_at IS NOT NULL 
                AND e.event_date > datetime('now')
            `;
            
            const conditions = [];
            const params = [];
            
            // Apply filters with parameterised queries
            if (filters.tech_stack) {
                conditions.push('e.tech_stack LIKE ?');
                params.push(`%${filters.tech_stack}%`);
            }
            
            if (filters.skill_level) {
                conditions.push('e.skill_level = ?');
                params.push(filters.skill_level);
            }
            
            if (filters.search) {
                conditions.push('(e.title LIKE ? OR e.description LIKE ?)');
                params.push(`%${filters.search}%`, `%${filters.search}%`);
            }
            
            if (conditions.length > 0) {
                query += ' AND ' + conditions.join(' AND ');
            }
            
            query += ' ORDER BY e.event_date ASC';
            
            global.db.all(query, params, (err, rows) => {
                if (err) {
                    console.error('Upcoming events query error:', err);
                    reject(err);
                } else {
                    const processedRows = rows.map(row => ({
                        ...row,
                        tech_stack: JSON.parse(row.tech_stack || '[]'),
                        co_hosts: JSON.parse(row.co_hosts || '[]'),
                        event_date: new Date(row.event_date),
                        published_at: new Date(row.published_at),
                        available_seats: (row.total_capacity || 0) - (row.confirmed_bookings || 0),
                        is_full: (row.confirmed_bookings || 0) >= (row.total_capacity || 0)
                    }));
                    resolve(processedRows);
                }
            });
        });
    }
    
    /**
     * Get detailed event information for booking page
     * @param {number} eventId - Event identifier
     * @returns {Promise<Object>} Detailed event with ticket types and availability
     */
    static async getEventForBooking(eventId) {
        return new Promise((resolve, reject) => {
            const query = `
                SELECT 
                    e.*,
                    (SELECT COUNT(*) FROM bookings b WHERE b.event_id = e.id AND b.booking_status = 'confirmed') as confirmed_bookings
                FROM gdg_events e 
                WHERE e.id = ? AND e.published_at IS NOT NULL AND e.event_date > datetime('now')
            `;
            
            global.db.get(query, [eventId], (err, row) => {
                if (err) {
                    reject(err);
                } else if (!row) {
                    resolve(null);
                } else {
                    const event = {
                        ...row,
                        tech_stack: JSON.parse(row.tech_stack || '[]'),
                        co_hosts: JSON.parse(row.co_hosts || '[]'),
                        event_date: new Date(row.event_date),
                        published_at: new Date(row.published_at)
                    };
                    
                    // Get ticket types with current availability
                    const ticketQuery = `
                        SELECT 
                            tt.*,
                            (SELECT COUNT(*) FROM bookings b WHERE b.ticket_type_id = tt.id AND b.booking_status = 'confirmed') as sold_tickets,
                            (tt.quantity_available - COALESCE((SELECT COUNT(*) FROM bookings b WHERE b.ticket_type_id = tt.id AND b.booking_status = 'confirmed'), 0)) as available_tickets
                        FROM ticket_types tt 
                        WHERE tt.event_id = ?
                        ORDER BY tt.is_member_only DESC, tt.price ASC
                    `;
                    
                    global.db.all(ticketQuery, [eventId], (ticketErr, ticketRows) => {
                        if (ticketErr) {
                            console.error('Ticket query error:', ticketErr);
                            reject(ticketErr);
                        } else {
                            console.log(`Found ${ticketRows.length} ticket types for event ${eventId}:`, ticketRows);
                            event.ticket_types = ticketRows.map(ticket => ({
                                ...ticket,
                                is_available: ticket.available_tickets > 0
                            }));
                            console.log('Processed ticket types:', event.ticket_types);
                            resolve(event);
                        }
                    });
                }
            });
        });
    }
    
    /**
     * Create new booking for attendee
     * @param {Object} bookingData - Booking details
     * @returns {Promise<number>} Created booking ID
     * @security Validates GDG membership via email and prevents overbooking
     */
    static async createBooking(bookingData) {
        return new Promise((resolve, reject) => {
            const { event_id, ticket_type_id, attendee_name, attendee_email, gdg_member_id } = bookingData;
            
            // First check ticket availability
            const availabilityQuery = `
                SELECT 
                    tt.*,
                    (tt.quantity_available - COALESCE((SELECT COUNT(*) FROM bookings b WHERE b.ticket_type_id = tt.id AND b.booking_status = 'confirmed'), 0)) as available_tickets
                FROM ticket_types tt
                WHERE tt.id = ? AND tt.event_id = ?
            `;
            
            global.db.get(availabilityQuery, [ticket_type_id, event_id], (availErr, ticket) => {
                if (availErr) {
                    reject(availErr);
                    return;
                }
                
                if (!ticket) {
                    reject(new Error('Invalid ticket type'));
                    return;
                }
                
                if (ticket.available_tickets <= 0) {
                    reject(new Error('No tickets available'));
                    return;
                }
                
                // Validate GDG membership if required
                if (ticket.is_member_only && (!gdg_member_id || !gdg_member_id.endsWith('@uol.eue.edu.eg'))) {
                    reject(new Error('Valid GDG membership required for this ticket type'));
                    return;
                }
                
                // Create the booking
                const bookingQuery = `
                    INSERT INTO bookings (event_id, ticket_type_id, attendee_name, attendee_email, gdg_member_id, booking_status)
                    VALUES (?, ?, ?, ?, ?, 'confirmed')
                `;
                
                const params = [event_id, ticket_type_id, attendee_name, attendee_email, gdg_member_id];
                
                global.db.run(bookingQuery, params, function(err) {
                    if (err) {
                        console.error('Booking creation error:', err);
                        reject(err);
                    } else {
                        resolve(this.lastID);
                    }
                });
            });
        });
    }
    
    /**
     * Verify GDG membership status
     * @param {string} email - Email address to verify
     * @returns {boolean} True if valid GDG member email
     * @business_rule GDG members must have @uol.eue.edu.eg email domain
     */
    static isValidGdgMember(email) {
        return email && email.endsWith('@uol.eue.edu.eg');
    }
    
    /**
     * Get unique tech stacks for filtering
     * @returns {Promise<Array>} Array of available tech stacks
     * @description Provides filter options for frontend
     */
    static async getAvailableTechStacks() {
        return new Promise((resolve, reject) => {
            const query = `
                SELECT DISTINCT tech_stack 
                FROM gdg_events 
                WHERE published_at IS NOT NULL 
                AND event_date > datetime('now')
            `;
            
            global.db.all(query, [], (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    const techStacks = new Set();
                    rows.forEach(row => {
                        const stacks = JSON.parse(row.tech_stack || '[]');
                        stacks.forEach(stack => techStacks.add(stack));
                    });
                    resolve(Array.from(techStacks).sort());
                }
            });
        });
    }
}

/**
 * Booking Validation Middleware
 * @security Comprehensive validation for booking form data
 */
const bookingValidation = [
    body('attendee_name')
        .isLength({ min: 2, max: 100 })
        .withMessage('Name must be between 2 and 100 characters')
        .matches(/^[a-zA-Z\s\-'\.]+$/)
        .withMessage('Name can only contain letters, spaces, hyphens, apostrophes, and periods')
        .trim()
        .escape(),
    body('attendee_email')
        .isEmail()
        .withMessage('Please provide a valid email address')
        .normalizeEmail()
        .isLength({ max: 320 })
        .withMessage('Email address is too long'),
    body('ticket_type_id')
        .isInt({ min: 1 })
        .withMessage('Please select a valid ticket type'),
    body('gdg_member_id')
        .optional({ checkFalsy: true })
        .isEmail()
        .withMessage('GDG member ID must be a valid email address')
        .custom((value) => {
            if (value && !value.endsWith('@uol.eue.edu.eg')) {
                throw new Error('GDG member ID must be a valid @uol.eue.edu.eg email address');
            }
            return true;
        })
        .normalizeEmail(),
    body('privacy_consent')
        .optional({ checkFalsy: true })
];

/**
 * @route GET /attendee
 * @desc Public home page for event discovery
 * @access Public
 * @description Displays upcoming workshops with filtering options
 */
router.get('/', async (req, res) => {
    try {
        const filters = {
            tech_stack: req.query.tech || '',
            skill_level: req.query.level ? parseInt(req.query.level) : null,
            search: req.query.q || ''
        };
        
        // Remove empty filters
        Object.keys(filters).forEach(key => {
            if (!filters[key]) delete filters[key];
        });
        
        const [events, techStacks] = await Promise.all([
            AttendeeService.getUpcomingEvents(filters),
            AttendeeService.getAvailableTechStacks()
        ]);
        
        res.render('attendee/index', {
            title: 'Upcoming Workshops - GDG EUE',
            description: 'Discover and book exciting tech workshops at European Universities in Egypt',
            events,
            techStacks,
            currentFilters: req.query,
            formatDate: (date) => format(date, 'EEEE, dd MMMM yyyy'),
            formatTime: (date) => format(date, 'HH:mm'),
            getSkillLevelName: (level) => {
                const levels = { 1: 'Beginner', 2: 'Intermediate', 3: 'Advanced' };
                return levels[level] || 'Unknown';
            },
            getSkillLevelClass: (level) => {
                const classes = { 1: 'skill-beginner', 2: 'skill-intermediate', 3: 'skill-advanced' };
                return classes[level] || '';
            }
        });
    } catch (error) {
        console.error('Attendee page error:', error);
        res.status(500).render('error/500', {
            title: 'Service Unavailable',
            message: 'Unable to load workshops. Please try again later.'
        });
    }
});

/**
 * @route GET /attendee/event/:id
 * @desc Event details and booking page
 * @access Public
 * @param {number} id - Event identifier
 * @description Displays detailed event information with booking form
 */
router.get('/event/:id', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID'),
    csrfProtection()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).redirect('/attendee');
        }
        
        const event = await AttendeeService.getEventForBooking(req.params.id);
        console.log(`Event ${req.params.id} loaded:`, event ? `${event.title} with ${event.ticket_types?.length || 0} tickets` : 'NOT FOUND');
        if (!event) {
            return res.status(404).render('error/404', {
                title: 'Workshop Not Found',
                message: 'The requested workshop is not available or has already ended.'
            });
        }
        
        res.render('attendee/event-details', {
            title: `${event.title} - GDG EUE`,
            event,
            csrfToken: req.csrfToken(),
            formatDate: (date) => format(date, 'EEEE, dd MMMM yyyy'),
            formatTime: (date) => format(date, 'HH:mm'),
            formatDuration: (minutes) => {
                const hours = Math.floor(minutes / 60);
                const mins = minutes % 60;
                return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
            },
            getSkillLevelName: (level) => {
                const levels = { 1: 'Beginner', 2: 'Intermediate', 3: 'Advanced' };
                return levels[level] || 'Unknown';
            },
            errors: []
        });
    } catch (error) {
        console.error('Event details error:', error);
        res.status(500).render('error/500', {
            title: 'Service Error',
            message: 'Unable to load event details. Please try again later.'
        });
    }
});

/**
 * @route POST /attendee/book/:id
 * @desc Process event booking
 * @access Public
 * @param {number} id - Event identifier
 * @validation Comprehensive booking data validation
 */
router.post('/book/:id', [
    param('id').isInt({ min: 1 }).withMessage('Invalid event ID'),
    csrfProtection(), // Move CSRF protection first
    ...bookingValidation
], async (req, res) => {
    try {
        const eventId = parseInt(req.params.id);
        console.log('Processing booking for event:', eventId);
        console.log('CSRF token received:', req.body._csrf);
        
        // Validate request
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('Validation errors:', errors.array());
            const event = await AttendeeService.getEventForBooking(eventId);
            return res.status(400).render('attendee/event-details', {
                title: `${event?.title || 'Event'} - GDG EUE`,
                event,
                csrfToken: req.csrfToken(),
                formatDate: (date) => format(date, 'EEEE, dd MMMM yyyy'),
                formatTime: (date) => format(date, 'HH:mm'),
                formatDuration: (minutes) => {
                    const hours = Math.floor(minutes / 60);
                    const mins = minutes % 60;
                    return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
                },
                getSkillLevelName: (level) => {
                    const levels = { 1: 'Beginner', 2: 'Intermediate', 3: 'Advanced' };
                    return levels[level] || 'Unknown';
                },
                errors: errors.array(),
                formData: req.body
            });
        }
        
        // Create booking
        const bookingData = {
            event_id: eventId,
            ticket_type_id: parseInt(req.body.ticket_type_id),
            attendee_name: req.body.attendee_name,
            attendee_email: req.body.attendee_email,
            gdg_member_id: req.body.gdg_member_id || null
        };
        
        console.log('Creating booking with data:', bookingData);
        const bookingId = await AttendeeService.createBooking(bookingData);
        console.log('Booking created successfully, ID:', bookingId);
        
        // Redirect to confirmation page
        res.redirect(`/attendee/booking-confirmation/${bookingId}`);
        
    } catch (error) {
        console.error('Booking error:', error);
        
        // Get event details for error display
        try {
            const event = await AttendeeService.getEventForBooking(parseInt(req.params.id));
            
            let errorMessage = 'Booking failed. Please try again.';
            if (error.message === 'No tickets available') {
                errorMessage = 'Sorry, this workshop is now fully booked.';
            } else if (error.message === 'Valid GDG membership required for this ticket type') {
                errorMessage = 'A valid GDG membership email (@uol.eue.edu.eg) is required for this ticket type.';
            }
            
            res.status(400).render('attendee/event-details', {
                title: `${event?.title || 'Event'} - GDG EUE`,
                event,
                csrfToken: req.csrfToken(),
                formatDate: (date) => format(date, 'EEEE, dd MMMM yyyy'),
                formatTime: (date) => format(date, 'HH:mm'),
                formatDuration: (minutes) => {
                    const hours = Math.floor(minutes / 60);
                    const mins = minutes % 60;
                    return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
                },
                getSkillLevelName: (level) => {
                    const levels = { 1: 'Beginner', 2: 'Intermediate', 3: 'Advanced' };
                    return levels[level] || 'Unknown';
                },
                errors: [{ msg: errorMessage }],
                formData: req.body
            });
        } catch (renderError) {
            console.error('Error rendering error page:', renderError);
            res.status(500).send('An error occurred while processing your booking.');
        }
    }
});

/**
 * @route GET /attendee/booking-confirmation/:id
 * @desc Booking confirmation page
 * @access Public
 * @param {number} id - Booking identifier
 * @description Displays booking confirmation with calendar download
 */
router.get('/booking-confirmation/:id', [
    param('id').isInt({ min: 1 }).withMessage('Invalid booking ID')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).redirect('/attendee');
        }
        
        // Get booking details with event information
        const query = `
            SELECT 
                b.*,
                e.title, e.description, e.event_date, e.duration_minutes, 
                tt.name as ticket_type_name, tt.price
            FROM bookings b
            JOIN gdg_events e ON b.event_id = e.id
            JOIN ticket_types tt ON b.ticket_type_id = tt.id
            WHERE b.id = ?
        `;
        
        global.db.get(query, [req.params.id], (err, booking) => {
            if (err) {
                console.error('Booking confirmation error:', err);
                return res.status(500).render('error/500', {
                    title: 'Confirmation Error',
                    message: 'Unable to load booking confirmation.'
                });
            }
            
            if (!booking) {
                return res.status(404).render('error/404', {
                    title: 'Booking Not Found',
                    message: 'The requested booking confirmation could not be found.'
                });
            }
            
            res.render('attendee/booking-confirmation', {
                title: 'Booking Confirmed - GDG EUE',
                booking: {
                    ...booking,
                    event_date: new Date(booking.event_date),
                    booking_date: new Date(booking.booking_date)
                },
                formatDate: (date) => format(date, 'EEEE, dd MMMM yyyy'),
                formatTime: (date) => format(date, 'HH:mm'),
                formatDuration: (minutes) => {
                    const hours = Math.floor(minutes / 60);
                    const mins = minutes % 60;
                    return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
                }
            });
        });
        
    } catch (error) {
        console.error('Booking confirmation error:', error);
        res.status(500).render('error/500', {
            title: 'Confirmation Error',
            message: 'Unable to load booking confirmation.'
        });
    }
});

/**
 * @route GET /attendee/api/availability/:eventId/:ticketTypeId
 * @desc Real-time ticket availability check
 * @access Public
 * @description AJAX endpoint for live availability updates
 */
router.get('/api/availability/:eventId/:ticketTypeId', [
    param('eventId').isInt({ min: 1 }),
    param('ticketTypeId').isInt({ min: 1 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Invalid parameters' });
        }
        
        const query = `
            SELECT 
                tt.*,
                (tt.quantity_available - COALESCE((SELECT COUNT(*) FROM bookings b WHERE b.ticket_type_id = tt.id AND b.booking_status = 'confirmed'), 0)) as available_tickets
            FROM ticket_types tt
            WHERE tt.id = ? AND tt.event_id = ?
        `;
        
        global.db.get(query, [req.params.ticketTypeId, req.params.eventId], (err, ticket) => {
            if (err) {
                console.error('Availability check error:', err);
                return res.status(500).json({ error: 'Availability check failed' });
            }
            
            if (!ticket) {
                return res.status(404).json({ error: 'Ticket type not found' });
            }
            
            res.json({
                available: ticket.available_tickets,
                total: ticket.quantity_available,
                isAvailable: ticket.available_tickets > 0
            });
        });
        
    } catch (error) {
        console.error('Availability API error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
