const { Pool } = require('pg');

const pool = new Pool({
  connectionString: 'postgres://postgres:Sup3rS3cretPassw0rd@db.qwertyuiopasdfgh.supabase.co:5432/postgres',
  ssl: { rejectUnauthorized: false },
});

module.exports = pool;
