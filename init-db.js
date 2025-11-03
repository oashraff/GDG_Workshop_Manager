const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error creating database:', err);
        process.exit(1);
    }
    console.log('✓ Database file created');
    
    const schema = fs.readFileSync('./db_schema.sql', 'utf8');
    
    db.exec(schema, (err) => {
        if (err) {
            console.error('Error executing schema:', err);
            process.exit(1);
        }
        console.log('✓ Database schema initialized successfully');
        console.log('✓ Sample data loaded');
        console.log('✓ Default admin user created (username: admin, password: gdgadmin2025)');
        
        db.close((err) => {
            if (err) {
                console.error('Error closing database:', err);
            } else {
                console.log('✓ Database initialization complete');
            }
            process.exit(0);
        });
    });
});
