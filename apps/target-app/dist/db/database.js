"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.db = void 0;
exports.initDatabase = initDatabase;
const sqlite3_1 = __importDefault(require("sqlite3"));
const config_1 = require("../config");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
// Ensure dir exists
const dbDir = path_1.default.dirname(config_1.config.dbPath);
if (!fs_1.default.existsSync(dbDir)) {
    fs_1.default.mkdirSync(dbDir, { recursive: true });
}
exports.db = new sqlite3_1.default.Database(config_1.config.dbPath);
function initDatabase() {
    return new Promise((resolve, reject) => {
        exports.db.serialize(() => {
            // Users table
            exports.db.run(`
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
            exports.db.run(`
        CREATE TABLE IF NOT EXISTS products (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          price REAL NOT NULL,
          description TEXT NOT NULL
        )
      `);
            // Seed Users
            exports.db.run(`
        INSERT OR REPLACE INTO users (id, username, password, role, email, api_key)
        VALUES 
          ('usr-001', 'admin', 'AdminPass2026!', 'ADMIN', 'admin@secureloop.io', 'sl_live_secret_key_8f921a9b'),
          ('usr-002', 'alice', 'AlicePass123!', 'USER', 'alice@company.com', 'sl_live_user_key_3c4d5e6f'),
          ('usr-003', 'bob', 'BobPassword99', 'USER', 'bob@company.com', 'sl_live_user_key_7a8b9c0d')
      `);
            // Seed Products
            exports.db.run(`
        INSERT OR REPLACE INTO products (id, name, category, price, description)
        VALUES 
          ('prod-1', 'Secure Gateway Appliance', 'Hardware', 2499.99, 'Enterprise edge security appliance'),
          ('prod-2', 'Cloud SIEM License', 'Software', 499.00, 'Monthly cloud SIEM log aggregator'),
          ('prod-3', 'Zero Trust Agent', 'Software', 19.99, 'Endpoint zero trust proxy service')
      `, (err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    });
}
