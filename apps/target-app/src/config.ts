import path from 'path';

export interface AppConfig {
  port: number;
  securityMode: 'VULNERABLE' | 'HARDENED';
  jwtSecret: string;
  logFilePath: string;
  dbPath: string;
  revokedTokens: Set<string>;
  blockedIps: Set<string>;
}

export const config: AppConfig = {
  port: parseInt(process.env.PORT || '8080', 10),
  securityMode: (process.env.SECURITY_MODE as 'VULNERABLE' | 'HARDENED') || 'VULNERABLE',
  jwtSecret: process.env.JWT_SECRET || 'secureloop-super-secret-key-2026',
  logFilePath: process.env.LOG_FILE_PATH || path.resolve(__dirname, '../../../pillar-2-shift-right/logs/app-telemetry.json'),
  dbPath: process.env.DB_PATH || path.resolve(__dirname, '../secureloop.db'),
  revokedTokens: new Set<string>(),
  blockedIps: new Set<string>()
};
