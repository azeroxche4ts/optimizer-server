const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

// Isolate test database and seed files so production state is NEVER modified
const testDbPath = path.join(__dirname, 'test-all-functions.db');
const testSeedPath = path.join(__dirname, 'test-all-functions-seed.json');
process.env.SQLITE_DB_PATH = testDbPath;
process.env.SEED_FILE_PATH = testSeedPath;
process.env.NODE_ENV = 'test';

// Clean up any stale files before db module opens the file
for (const p of [testDbPath, `${testDbPath}-wal`, `${testDbPath}-shm`, testSeedPath, `${testSeedPath}.backup`]) {
    try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch {}
}

const auth = require('../auth');
const { config, resolveConfig, validateConfig, getSanitizedConfig, safeTimingCompare, parseEnvFile } = require('../config');
const db = require('../db');
const { app } = require('../server');

function makeRequest(server, options = {}) {
    return new Promise((resolve, reject) => {
        const addr = server.address();
        const req = http.request({
            host: '127.0.0.1',
            port: addr.port,
            path: options.path || '/',
            method: options.method || 'GET',
            headers: options.headers || {}
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let parsed = data;
                try { parsed = JSON.parse(data); } catch {}
                resolve({ status: res.statusCode, headers: res.headers, body: parsed });
            });
        });
        req.on('error', reject);
        if (options.body) {
            req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
        }
        req.end();
    });
}

test('Comprehensive Function & Route Suite', async (t) => {
    let server;
    let adminToken;
    const testAdminHeader = () => ({
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
    });

    t.before(async () => {
        await db.initDatabase();
        server = http.createServer(app);
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

        const res = await makeRequest(server, {
            path: '/api/auth/admin/login',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: { username: 'MADARA-FF', password: 'ABHISHEK!' }
        });
        assert.strictEqual(res.status, 200);
        adminToken = res.body.token;
        assert.ok(adminToken, 'Admin token should be acquired');
    });

    t.after(async () => {
        if (server) await new Promise(resolve => server.close(resolve));
        db.closeDatabase();
        for (const p of [testDbPath, `${testDbPath}-wal`, `${testDbPath}-shm`, testSeedPath, `${testSeedPath}.backup`]) {
            try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch {}
        }
    });

    // ==========================================
    // SECTION 1: AUTH MODULE TESTS
    // ==========================================
    await t.test('1. Auth Module: generate, hash, last4, validFormat, password, rateLimiter', () => {
        const key1 = auth.generateLicenseKey();
        assert.ok(key1.startsWith('AZEROX-'), 'Default prefix AZEROX');
        assert.strictEqual(auth.isValidKeyFormat(key1), true);

        const key2 = auth.generateLicenseKey('OPTIMIZER');
        assert.ok(key2.startsWith('OPTIMIZER-'), 'Custom prefix OPTIMIZER');
        assert.strictEqual(auth.isValidKeyFormat(key2), true);

        assert.strictEqual(auth.isValidKeyFormat('MADARA-FF-1234-5678-ABCD-EFGH'), true);
        assert.strictEqual(auth.isValidKeyFormat('INVALID_KEY'), false);
        assert.strictEqual(auth.isValidKeyFormat(''), false);
        assert.strictEqual(auth.isValidKeyFormat(null), false);

        const hash = auth.hashKey(key1);
        assert.strictEqual(hash.length, 64);
        assert.strictEqual(auth.hashKey(''), '');

        const last4 = auth.getKeyLast4(key1);
        assert.strictEqual(last4.length, 4);
        assert.strictEqual(auth.getKeyLast4(''), '');

        const pwdHash = auth.hashPassword('SecretPass123!');
        assert.ok(pwdHash.salt && pwdHash.hash);
        assert.strictEqual(auth.verifyPassword('SecretPass123!', pwdHash.salt, pwdHash.hash), true);
        assert.strictEqual(auth.verifyPassword('WrongPass', pwdHash.salt, pwdHash.hash), false);
        assert.strictEqual(auth.verifyPassword('', pwdHash.salt, pwdHash.hash), false);

        const token = auth.generateToken();
        assert.strictEqual(token.length, 64);

        const limiter = new auth.RateLimiter(2, 1000);
        assert.strictEqual(limiter.isRateLimited('1.2.3.4'), false);
        assert.strictEqual(limiter.isRateLimited('1.2.3.4'), false);
        assert.strictEqual(limiter.isRateLimited('1.2.3.4'), true);
        limiter.cleanup();
    });

    // ==========================================
    // SECTION 2: CONFIG MODULE TESTS
    // ==========================================
    await t.test('2. Config Module: resolution, validation, sanitization, timing compare', () => {
        const testEnv = {
            NODE_ENV: 'production',
            ADMIN_SECRET: 'super_secret_production_key_12345678',
            ADMIN_PASSWORD: 'custom_strong_password_9876',
            PORT: '8080'
        };
        const resolved = resolveConfig(testEnv);
        assert.strictEqual(resolved.isProduction, true);
        assert.strictEqual(resolved.port, 8080);

        const validation = validateConfig(resolved);
        assert.strictEqual(validation.valid, true);

        const badValidation = validateConfig({ ...resolved, adminSecret: '', port: -1 });
        assert.strictEqual(badValidation.valid, false);
        assert.ok(badValidation.errors.length >= 2);

        const sanitized = getSanitizedConfig(resolved);
        assert.strictEqual(sanitized.adminSecretSet, true);
        assert.ok(sanitized.adminSecretMasked.includes('REDACTED'));

        assert.strictEqual(safeTimingCompare('hello', 'hello'), true);
        assert.strictEqual(safeTimingCompare('hello', 'world'), false);
        assert.strictEqual(safeTimingCompare('hello', 'hell'), false);
        assert.strictEqual(safeTimingCompare(null, 'hello'), false);
    });

    // ==========================================
    // SECTION 3: DB MODULE TESTS
    // ==========================================
    await t.test('3. DB Module: Admin & Sessions', async () => {
        const admin = await db.getAdminByUsername('MADARA-FF');
        assert.ok(admin);
        assert.strictEqual(admin.username, 'MADARA-FF');

        const adminById = await db.getAdminById(admin.id);
        assert.strictEqual(adminById.username, 'MADARA-FF');

        await db.createAdmin('SUBADMIN', 'Pass1234!', 'sub@root.com', 'admin');
        const subAdmin = await db.getAdminByUsername('SUBADMIN');
        assert.ok(subAdmin);

        await db.updateAdminPassword(subAdmin.id, 'NewPass1234!');
        const updatedSub = await db.getAdminByUsername('SUBADMIN');
        assert.strictEqual(auth.verifyPassword('NewPass1234!', updatedSub.salt, updatedSub.password_hash), true);

        const testTok = 'test_token_' + Date.now();
        const expFuture = new Date(Date.now() + 60000);
        await db.createAdminSession(subAdmin.id, testTok, expFuture);
        const session = await db.getAdminSession(testTok);
        assert.ok(session);
        assert.strictEqual(session.username, 'SUBADMIN');

        await db.deleteAdminSession(testTok);
        const deadSession = await db.getAdminSession(testTok);
        assert.strictEqual(deadSession, null);
    });

    await t.test('4. DB Module: Products & Releases', async () => {
        const prod = await db.getOrCreateProduct('OPTIMIZE', 'Main Optimizer Product');
        assert.ok(prod.id);
        const prodSame = await db.getOrCreateProduct('OPTIMIZE');
        assert.strictEqual(prod.id, prodSame.id);

        const allProds = await db.getAllProducts();
        assert.ok(allProds.some(p => p.name === 'OPTIMIZE'));

        const rel = await db.saveAppRelease({
            latest_version: '2.0.0',
            version_code: 50,
            min_version: '1.0.0',
            title: 'Release v2.0.0',
            release_notes: 'Full functional suite release',
            download_url: '/api/app/download'
        });
        assert.ok(rel);

        const latestRel = await db.getLatestAppRelease();
        assert.strictEqual(latestRel.latest_version, '2.0.0');

        const allRels = await db.getAllAppReleases(5);
        assert.ok(allRels.length >= 1);
    });

    await t.test('5. DB Module: Keys, Activations, Extend, Reduce, and Delete', async () => {
        const prod = await db.getOrCreateProduct('OPTIMIZE');
        const rawKey = auth.generateLicenseKey('OPTIMIZER');
        const keyRecord = await db.createActivationKey({
            keyString: rawKey,
            productId: prod.id,
            durationHours: 24,
            maxDevices: 2,
            customerName: 'TestCustomer',
            notes: 'Test key note'
        });
        assert.ok(keyRecord.id);
        assert.strictEqual(keyRecord.status, 'UNUSED');

        const fetchedHash = await db.getKeyByHash(auth.hashKey(rawKey));
        assert.strictEqual(fetchedHash.id, keyRecord.id);

        const fetchedIdOrStr = await db.getKeyByIdOrString(rawKey);
        assert.strictEqual(fetchedIdOrStr.id, keyRecord.id);

        const cust = await db.getOrCreateCustomer('cust_001', 'Customer One');
        const dev = await db.getOrCreateDevice(cust.id, 'dev_ident_001', 'Pixel 8', 'com.app', 'Android');
        assert.ok(dev.id);

        const sessTok = auth.generateToken();
        const expTime = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
        await db.recordActivation({
            keyId: keyRecord.id,
            customerId: cust.id,
            deviceId: dev.id,
            expiresAt: expTime,
            sessionToken: sessTok
        });

        const actFound = await db.findActivation(keyRecord.id, dev.id);
        assert.ok(actFound);
        assert.strictEqual(actFound.device_identifier, 'dev_ident_001');

        const actCount = await db.getActiveActivationsCount(keyRecord.id);
        assert.strictEqual(actCount, 1);

        const acts = await db.getKeyActivations(keyRecord.id);
        assert.strictEqual(acts.length, 1);

        const devKey = await db.getKeyByDeviceOrSession('dev_ident_001', sessTok);
        assert.ok(devKey);
        assert.strictEqual(devKey.id, keyRecord.id);

        // Update key status to ACTIVE with an expiration time
        await db.updateKeyDetails(keyRecord.id, {
            status: 'ACTIVE',
            activatedAt: new Date().toISOString(),
            expiresAt: expTime
        });
        checkKey = await db.getKeyById(keyRecord.id);
        assert.strictEqual(checkKey.status, 'ACTIVE');

        // Extend key expiry
        const extended = await db.extendKeyExpiry(keyRecord.id, 24);
        assert.ok(new Date(extended.expires_at).getTime() > new Date(expTime).getTime());

        // Reduce key time
        const reduced = await db.reduceKeyTime(keyRecord.id, 5, 'admin');
        assert.ok(new Date(reduced.newExpiresAt).getTime() < new Date(extended.expires_at).getTime());

        // Update key details
        const updatedDetails = await db.updateKeyDetails(keyRecord.id, {
            notes: 'Updated note',
            customerName: 'Renamed Customer',
            maxDevices: 3
        });
        assert.strictEqual(updatedDetails.notes, 'Updated note');
        assert.strictEqual(updatedDetails.customer_name, 'Renamed Customer');
        assert.strictEqual(updatedDetails.max_devices, 3);

        // Audit log
        await db.logAuditEvent('TEST_EVENT', { sample: 123 });
        const recentLogs = await db.getRecentLogs(10);
        assert.ok(recentLogs.some(l => l.event_type === 'TEST_EVENT'));

        // Dashboard Stats
        const stats = await db.getDashboardStats();
        assert.ok(stats.total_keys >= 1);
        assert.ok(stats.active_keys >= 1);

        // Deactivate device
        await db.deactivateDevice(keyRecord.id, dev.id);
        const actCountAfter = await db.getActiveActivationsCount(keyRecord.id);
        assert.strictEqual(actCountAfter, 0);

        // Delete key
        const delRes = await db.deleteKey(keyRecord.id, 'admin', 'Test deletion');
        assert.strictEqual(delRes.success, true);
        assert.strictEqual(await db.isKeyDeleted(auth.hashKey(rawKey)), true);

        const deletedList = await db.getAllDeletedKeys();
        assert.ok(deletedList.some(d => d.key_hash === auth.hashKey(rawKey)));
    });

    // ==========================================
    // SECTION 4: SERVER API ROUTES
    // ==========================================
    await t.test('6. Server API: Key Generation & Listing', async () => {
        // Generate a 1-day key
        const genRes = await makeRequest(server, {
            path: '/api/keys/generate',
            method: 'POST',
            headers: testAdminHeader(),
            body: {
                product_name: 'OPTIMIZE',
                duration_hours: 24,
                max_devices: 2,
                customer_name: 'ApiUser',
                notes: 'API generated'
            }
        });
        assert.strictEqual(genRes.status, 200);
        assert.strictEqual(genRes.body.success, true);
        const generatedKey = genRes.body.keys[0];
        assert.ok(generatedKey.key);

        // List keys
        const listRes = await makeRequest(server, {
            path: '/api/keys?status=ALL',
            method: 'GET',
            headers: testAdminHeader()
        });
        assert.strictEqual(listRes.status, 200);
        assert.ok(listRes.body.keys.some(k => k.key_display === generatedKey.key_display));

        // Bulk Key Generation (5 keys)
        const bulkGenRes = await makeRequest(server, {
            path: '/api/keys/generate',
            method: 'POST',
            headers: testAdminHeader(),
            body: {
                product_name: 'OPTIMIZE',
                duration_hours: 720,
                max_devices: 1,
                count: 5,
                prefix: 'BULK'
            }
        });
        assert.strictEqual(bulkGenRes.status, 200);
        assert.strictEqual(bulkGenRes.body.success, true);
        assert.strictEqual(bulkGenRes.body.keys.length, 5);
        for (const k of bulkGenRes.body.keys) {
            assert.ok(k.key.startsWith('BULK-'), 'Each bulk key must start with prefix BULK');
            assert.strictEqual(k.duration_hours, 720);
            assert.strictEqual(k.status, 'UNUSED');
        }

        // Get single key
        const singleRes = await makeRequest(server, {
            path: `/api/keys/${generatedKey.id}`,
            method: 'GET',
            headers: testAdminHeader()
        });
        assert.strictEqual(singleRes.status, 200);
        assert.strictEqual(singleRes.body.key.id, generatedKey.id);

        // Pause key
        const pauseRes = await makeRequest(server, {
            path: `/api/keys/${generatedKey.id}/pause`,
            method: 'POST',
            headers: testAdminHeader()
        });
        assert.strictEqual(pauseRes.status, 200);
        assert.strictEqual(pauseRes.body.key.status, 'PAUSED');

        // Resume key
        const resumeRes = await makeRequest(server, {
            path: `/api/keys/${generatedKey.id}/resume`,
            method: 'POST',
            headers: testAdminHeader()
        });
        assert.strictEqual(resumeRes.status, 200);

        // Extend key
        const extendRes = await makeRequest(server, {
            path: `/api/keys/${generatedKey.id}/extend`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { hours: 24 }
        });
        assert.strictEqual(extendRes.status, 200);

        // Reduce key
        const reduceRes = await makeRequest(server, {
            path: `/api/keys/${generatedKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: 2, unit: 'hours' }
        });
        assert.strictEqual(reduceRes.status, 200);

        // Patch key
        const patchRes = await makeRequest(server, {
            path: `/api/keys/${generatedKey.id}`,
            method: 'PATCH',
            headers: testAdminHeader(),
            body: { notes: 'Updated via PATCH' }
        });
        assert.strictEqual(patchRes.status, 200);
        assert.strictEqual(patchRes.body.key.notes, 'Updated via PATCH');
    });

    await t.test('7. Server API: Client Activation Flow & Validation', async () => {
        // Generate clean key for client testing
        const genRes = await makeRequest(server, {
            path: '/api/keys/generate',
            method: 'POST',
            headers: testAdminHeader(),
            body: { product_name: 'OPTIMIZE', duration_hours: 24, max_devices: 1 }
        });
        const clientKey = genRes.body.keys[0].key_display;

        // Activate device
        const actRes = await makeRequest(server, {
            path: '/api/activate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: clientKey,
                device_id: 'client_device_test_101',
                device_model: 'Google Pixel 8',
                product: 'OPTIMIZE'
            }
        });
        assert.strictEqual(actRes.status, 200);
        assert.strictEqual(actRes.body.success, true);
        assert.strictEqual(actRes.body.status, 'ACTIVE');
        const sessionToken = actRes.body.session_token;
        assert.ok(sessionToken);

        // Validate license
        const valRes = await makeRequest(server, {
            path: '/api/license/validate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: clientKey,
                device_id: 'client_device_test_101',
                session_token: sessionToken,
                product: 'OPTIMIZE'
            }
        });
        assert.strictEqual(valRes.status, 200);
        assert.strictEqual(valRes.body.valid, true);

        // Product mismatch validation rejection
        const mismatchRes = await makeRequest(server, {
            path: '/api/license/validate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: clientKey,
                device_id: 'client_device_test_101',
                product: 'DIFFERENT_PRODUCT'
            }
        });
        assert.strictEqual(mismatchRes.status, 403);
        assert.strictEqual(mismatchRes.body.code, 'PRODUCT_MISMATCH');

        // Deactivate device
        const deactRes = await makeRequest(server, {
            path: '/api/deactivate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: clientKey,
                device_id: 'client_device_test_101'
            }
        });
        assert.strictEqual(deactRes.status, 200);
        assert.strictEqual(deactRes.body.success, true);
    });

    await t.test('8. Server API: Health, Config, App Version & Download', async () => {
        const healthRes = await makeRequest(server, { path: '/api/health', method: 'GET' });
        assert.strictEqual(healthRes.status, 200);
        assert.strictEqual(healthRes.body.status, 'ok');

        const cfgStatusRes = await makeRequest(server, {
            path: '/api/config/status',
            method: 'GET',
            headers: testAdminHeader()
        });
        assert.strictEqual(cfgStatusRes.status, 200);
        assert.strictEqual(cfgStatusRes.body.success, true);

        const verRes = await makeRequest(server, { path: '/api/app/version', method: 'GET' });
        assert.strictEqual(verRes.status, 200);
        assert.ok(verRes.body.latest_version);

        // Download endpoint
        const dlRes = await makeRequest(server, { path: '/api/app/download', method: 'GET' });
        assert.strictEqual(dlRes.status, 200);
        assert.strictEqual(dlRes.headers['accept-ranges'], 'bytes');

        // Range request
        const rangeRes = await makeRequest(server, {
            path: '/api/app/download',
            method: 'GET',
            headers: { 'Range': 'bytes=0-10' }
        });
        assert.strictEqual(rangeRes.status, 206);
    });

    await t.test('9. Server API: Export, Backup, Clear Keys, and Purge', async () => {
        const expRes = await makeRequest(server, {
            path: '/api/keys/export',
            method: 'GET',
            headers: testAdminHeader()
        });
        assert.strictEqual(expRes.status, 200);
        assert.ok(Array.isArray(expRes.body.keys));

        const backupRes = await makeRequest(server, {
            path: '/api/admin/keys/backup',
            method: 'GET',
            headers: testAdminHeader()
        });
        assert.strictEqual(backupRes.status, 200);
        assert.ok(Array.isArray(backupRes.body.keys));

        // Clear expired
        const clrExpRes = await makeRequest(server, {
            path: '/api/keys/clear-expired',
            method: 'POST',
            headers: testAdminHeader()
        });
        assert.strictEqual(clrExpRes.status, 200);

        // Clear active
        const clrActRes = await makeRequest(server, {
            path: '/api/keys/clear-active',
            method: 'POST',
            headers: testAdminHeader()
        });
        assert.strictEqual(clrActRes.status, 200);

        // Clear all keys
        const clrAllRes = await makeRequest(server, {
            path: '/api/keys/clear-all',
            method: 'POST',
            headers: testAdminHeader()
        });
        assert.strictEqual(clrAllRes.status, 200);
    });
});
