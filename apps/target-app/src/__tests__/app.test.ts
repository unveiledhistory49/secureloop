import request from 'supertest';
import app from '../index';
import { config } from '../config';

describe('SecureLoop Target App Integration Tests', () => {
  beforeEach(() => {
    config.securityMode = 'VULNERABLE';
  });

  test('GET /health returns 200 and HEALTHY status', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('HEALTHY');
  });

  test('VULNERABLE mode: SQL Injection in /api/search', async () => {
    const res = await request(app).get("/api/search?q=' OR '1'='1");
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('VULNERABLE');
    expect(res.body.results.length).toBeGreaterThan(0);
  });

  test('HARDENED mode: SQL Injection is sanitized', async () => {
    config.securityMode = 'HARDENED';
    const res = await request(app).get("/api/search?q=' OR '1'='1");
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('HARDENED');
    expect(res.body.results.length).toBe(0);
  });

  test('VULNERABLE mode: Command Injection in /api/export', async () => {
    const res = await request(app)
      .post('/api/export')
      .send({ filename: 'test', format: 'txt$(id)' });
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('VULNERABLE');
    expect(res.body.output).toContain('uid=');
  });

  test('HARDENED mode: Command Injection is sanitized', async () => {
    config.securityMode = 'HARDENED';
    const res = await request(app)
      .post('/api/export')
      .send({ filename: 'test', format: 'txt; id' });
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('HARDENED');
    expect(res.body.filename).toBe('test.txtid');
  });

  test('VULNERABLE mode: SSRF blocks/fetches local metadata', async () => {
    const res = await request(app).get('/api/fetch-url?url=http://127.0.0.1:8080/health');
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('VULNERABLE');
  });

  test('HARDENED mode: SSRF blocks private subnets', async () => {
    config.securityMode = 'HARDENED';
    const res = await request(app).get('/api/fetch-url?url=http://169.254.169.254/latest/meta-data/');
    expect(res.status).toBe(403);
    expect(res.body.mode).toBe('HARDENED');
  });
});
