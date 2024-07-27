import mysql from 'mysql2/promise';

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'password',
    port: parseInt(process.env.DB_PORT || '3306'),
    database: process.env.DB_DATABASE || 'test',
    // pool options:
    waitForConnections: 'true' === (process.env.DB_WAIT_FOR_CONNECTIONS || 'true'),
    connectionLimit: parseInt(process.env.DB_COLLECTION_LIMIT || 20),
    enableKeepAlive: 'true' === (process.env.DB_ENABLE_KEEP_ALIVE || 'true'),
    idleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '60000'),
    maxIdle: parseInt(process.env.DB_MAX_IDLE || '2')
});

export async function dbQueryAll(sql, ...args) {
    if (Array.isArray(sql)) {
        sql = sql.join('?');
    }
    console.log(`[sql-query] ${sql}, args=${args}`);
    try {
        const [rows, fields] = await pool.query(sql, args);
        return rows;
    } catch (err) {
        console.error(err);
        throw err;
    }
}

export async function dbQueryFirst(sql, ...args) {
    let rows = await dbQueryAll(sql, args);
    if (rows.length > 0) {
        return rows[0];
    }
    return null;
}

export async function dbExecute(sql, ...args) {
    if (Array.isArray(sql)) {
        sql = sql.join('?');
    }
    console.log(`[sql-execute] ${sql}, args=${args}`);
    try {
        const [result, fields] = await pool.execute(sql, args);
        console.log(result);
        console.log(fields);
        return [result, fields];
    } catch (err) {
        console.error(err);
        throw err;
    }
}

export async function dbInsert(table, obj) {
    const keys = Object.keys(obj);
    const placeholders = keys.map(key => '?');
    const values = keys.map(key => obj[key]);
    const sql = `INSERT INTO ${table} (${keys}) VALUES (${placeholders})`;
    await dbExecute(sql, ...values);
}

export async function dbUpdate(table, obj, ...keys) {
    const sets = keys.map(key => key + '=?');
    const values = keys.map(key => obj[key]);
    values.push(obj.id);
    const sql = `UPDATE ${table} SET ${sets} WHERE id=?`;
    await dbExecute(sql, ...values);
}
