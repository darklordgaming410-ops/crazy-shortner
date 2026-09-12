import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

function sanitizeArgs(args) {
  return args.map(arg => {
    if (arg === undefined) return null;
    if (typeof arg === 'boolean') return arg ? 1 : 0;
    return arg;
  });
}

function createPreparedStatement(db, sql, initialArgs = []) {
  const stmt = db.prepare(sql);
  const boundArgs = sanitizeArgs(initialArgs);

  return {
    bind(...args) {
      return createPreparedStatement(db, sql, args);
    },
    async first(col) {
      const row = stmt.get(...boundArgs);
      if (!row) return null;
      if (typeof col === 'string') {
        return row[col] !== undefined ? row[col] : null;
      }
      return row;
    },
    async all() {
      const results = stmt.all(...boundArgs);
      return { success: true, results };
    },
    async run() {
      const info = stmt.run(...boundArgs);
      return {
        success: true,
        meta: {
          changes: Number(info.changes || 0),
          last_row_id: Number(info.lastInsertRowid || 0)
        }
      };
    }
  };
}

export function createD1(dbFilePath) {
  const resolvedPath = dbFilePath || path.join(process.cwd(), 'teleshort.db');
  const db = new DatabaseSync(resolvedPath);

  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA journal_mode = WAL;');

  // Run schema.sql if users table does not exist
  const tableCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();
  if (!tableCheck) {
    const schemaPath = path.join(process.cwd(), 'schema.sql');
    if (fs.existsSync(schemaPath)) {
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      db.exec(schemaSql);
    }
  }

  // Ensure at least one active visit step and website exists so short links work immediately
  try {
    const stepCount = db.prepare('SELECT COUNT(*) n FROM visit_steps').get();
    if (!stepCount || Number(stepCount.n || 0) === 0) {
      db.exec(`
        INSERT OR IGNORE INTO visit_steps (id, step_number, title, description, wait_seconds, enabled)
        VALUES ('step_default_1', 1, 'Verification Step', 'Visit the sponsor website to unlock your destination link', 5, 1);

        INSERT OR IGNORE INTO step_websites (id, step_id, title, url, position, enabled)
        VALUES ('site_default_1', 'step_default_1', 'Example Sponsor', 'https://example.com', 1, 1);
      `);
    }
  } catch (err) {
    console.warn('Initial step check warning:', err.message);
  }

  return {
    prepare(sql) {
      return createPreparedStatement(db, sql);
    },
    async batch(statements) {
      db.exec('BEGIN TRANSACTION');
      try {
        const results = [];
        for (const s of statements) {
          const res = await s.run();
          results.push(res);
        }
        db.exec('COMMIT');
        return results;
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
    exec(sql) {
      db.exec(sql);
    },
    close() {
      db.close();
    }
  };
}
