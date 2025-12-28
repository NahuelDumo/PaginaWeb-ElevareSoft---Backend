const { query } = require('./db');

(async () => {
    try {
        console.log("Initializing Database...");
        const createUsersTableMsg = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                reset_token VARCHAR(255),
                reset_token_expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `;
        await query(createUsersTableMsg);
        console.log("Table 'users' is ready.");

        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS proposals (
                id SERIAL PRIMARY KEY,
                access_token VARCHAR(255) UNIQUE NOT NULL,
                client_name VARCHAR(255),
                status VARCHAR(50) DEFAULT 'pendiente',
                data JSONB,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
        `;
        await query(createTableQuery);
        console.log("Table 'proposals' is ready.");
        process.exit(0);
    } catch (err) {
        console.error("Error creating table:", err);
        process.exit(1);
    }
})();
