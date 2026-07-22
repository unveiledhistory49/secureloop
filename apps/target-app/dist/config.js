"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
const path_1 = __importDefault(require("path"));
exports.config = {
    port: parseInt(process.env.PORT || '8080', 10),
    securityMode: process.env.SECURITY_MODE || 'VULNERABLE',
    jwtSecret: process.env.JWT_SECRET || 'secureloop-super-secret-key-2026',
    logFilePath: process.env.LOG_FILE_PATH || path_1.default.resolve(__dirname, '../../../pillar-2-shift-right/logs/app-telemetry.json'),
    dbPath: process.env.DB_PATH || path_1.default.resolve(__dirname, '../secureloop.db'),
    revokedTokens: new Set(),
    blockedIps: new Set()
};
