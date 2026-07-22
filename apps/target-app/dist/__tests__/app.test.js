"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const index_1 = __importDefault(require("../index"));
const config_1 = require("../config");
describe('SecureLoop Target App Integration Tests', () => {
    beforeEach(() => {
        config_1.config.securityMode = 'VULNERABLE';
    });
    test('GET /health returns 200 and HEALTHY status', async () => {
        const res = await (0, supertest_1.default)(index_1.default).get('/health');
        expect(res.status).toBe(200);
        expect(res.body.status).toBe('HEALTHY');
    });
    test('VULNERABLE mode: SQL Injection in /api/search', async () => {
        const res = await (0, supertest_1.default)(index_1.default).get("/api/search?q=' OR '1'='1");
        expect(res.status).toBe(200);
        expect(res.body.mode).toBe('VULNERABLE');
        expect(res.body.results.length).toBeGreaterThan(0);
    });
    test('HARDENED mode: SQL Injection is sanitized', async () => {
        config_1.config.securityMode = 'HARDENED';
        const res = await (0, supertest_1.default)(index_1.default).get("/api/search?q=' OR '1'='1");
        expect(res.status).toBe(200);
        expect(res.body.mode).toBe('HARDENED');
        expect(res.body.results.length).toBe(0);
    });
    test('VULNERABLE mode: Command Injection in /api/export', async () => {
        const res = await (0, supertest_1.default)(index_1.default)
            .post('/api/export')
            .send({ filename: 'test', format: 'txt$(id)' });
        expect(res.status).toBe(200);
        expect(res.body.mode).toBe('VULNERABLE');
        expect(res.body.output).toContain('uid=');
    });
    test('HARDENED mode: Command Injection is sanitized', async () => {
        config_1.config.securityMode = 'HARDENED';
        const res = await (0, supertest_1.default)(index_1.default)
            .post('/api/export')
            .send({ filename: 'test', format: 'txt; id' });
        expect(res.status).toBe(200);
        expect(res.body.mode).toBe('HARDENED');
        expect(res.body.filename).toBe('test.txtid');
    });
    test('VULNERABLE mode: SSRF blocks/fetches local metadata', async () => {
        const res = await (0, supertest_1.default)(index_1.default).get('/api/fetch-url?url=http://127.0.0.1:8080/health');
        expect(res.status).toBe(200);
        expect(res.body.mode).toBe('VULNERABLE');
    });
    test('HARDENED mode: SSRF blocks private subnets', async () => {
        config_1.config.securityMode = 'HARDENED';
        const res = await (0, supertest_1.default)(index_1.default).get('/api/fetch-url?url=http://169.254.169.254/latest/meta-data/');
        expect(res.status).toBe(403);
        expect(res.body.mode).toBe('HARDENED');
    });
});
