import sqlite3 from 'sqlite3';
import { config } from '../config';
import fs from 'fs';
import path from 'path';

// Ensure dir exists
const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

export const db = new sqlite3.Database(config.dbPath);

export function initDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Users table
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          role TEXT NOT NULL,
          email TEXT NOT NULL,
          api_key TEXT NOT NULL
        )
      `);

      // Products table
      db.run(`
        CREATE TABLE IF NOT EXISTS products (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          price REAL NOT NULL,
          description TEXT NOT NULL
        )
      `);

      // Seed Users
      db.run(`
        INSERT OR REPLACE INTO users (id, username, password, role, email, api_key)
        VALUES 
          ('usr-001', 'admin', 'AdminPass2026!', 'ADMIN', 'admin@secureloop.io', 'sl_live_secret_key_8f921a9b'),
          ('usr-002', 'alice', 'AlicePass123!', 'USER', 'alice@company.com', 'sl_live_user_key_3c4d5e6f'),
          ('usr-003', 'bob', 'BobPassword99', 'USER', 'bob@company.com', 'sl_live_user_key_7a8b9c0d')
      `);

      // Seed Products
      db.run(`
        INSERT OR REPLACE INTO products (id, name, category, price, description)
        VALUES 
          ('prod-1', 'Secure Gateway Appliance', 'Hardware', 2499.99, 'Enterprise edge security appliance'),
          ('prod-2', 'Cloud SIEM License', 'Software', 499.00, 'Monthly cloud SIEM log aggregator'),
          ('prod-3', 'Zero Trust Agent', 'Software', 19.99, 'Endpoint zero trust proxy service')
      `, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  });
}
