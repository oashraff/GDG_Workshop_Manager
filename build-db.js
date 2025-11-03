/**
 * Database Builder Script
 * Builds SQLite database from schema file using sqlite3 npm package
 */

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const DB_PATH = path.join(__dirname, 'database.db');
const SCHEMA_PATH = path.join(__dirname, 'db_schema.sql');

// Remove existing database if it exists
if (fs.existsSync(DB_PATH)) {
    fs.unlinkSync(DB_PATH);
    console.log('✓ Removed existing database');
}

// Read SQL schema
const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');

// Create new database
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('✗ Error creating database:', err.message);
        process.exit(1);
    }
    console.log('✓ Database file created');
});

// Execute schema
db.exec(schema, (err) => {
    if (err) {
        console.error('✗ Error executing schema:', err.message);
        db.close();
        process.exit(1);
    }
    
    console.log('✓ Schema executed successfully');
    console.log('✓ Sample data inserted');
    
    // Close database
    db.close((err) => {
        if (err) {
            console.error('✗ Error closing database:', err.message);
            process.exit(1);
        }
        console.log('✓ Database built successfully!');
        process.exit(0);
    });
});
