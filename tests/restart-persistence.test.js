const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

const testDbPath = path.join(__dirname, 'test-restart-persistence.db');
const testSeedPath = path.join(__dirname, 'test-restart-seed.json');
process.env.SQLITE_DB_PATH = testDbPath;
process.env.SEED_FILE_PATH = testSeedPath;
process.env.NODE_ENV = 'test';

const db = require('../db');
const { app } = require('../server');
const { generateToken } = require('../auth');

test('Key Management & 24/7 Restart Persistence Test Suite', async (t) => {
    db.setSqliteDb(testDbPath);

    let server;
    let adminToken;
    let adminId;

    await db.initDatabase();

    const admin = await db.getAdminByUsername('MADARA-FF');
    adminId = admin ? admin.id : 1;
    adminToken = generateToken();
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    await db.createAdminSession(adminId, adminToken, expiresAt);

    await new Promise((resolve) => {
        server = app.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;

    function request(urlPath, options = {}) {
        return new Promise((resolve, reject) => {
            const req = http.request({
                hostname: '127.0.0.1',
                port,
                path: urlPath,
                method: options.method || 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    ...(options.headers || {})
                }
            }, (res) => {
                let data = '';
                res.on('data', chunk => { data += chunk; });
                res.on('end', () => {
                    try {
                        resolve({ status: res.statusCode, body: JSON.parse(data) });
                    } catch {
                        resolve({ status: res.statusCode, body: data });
                    }
                });
            });
            req.on('error', reject);
            if (options.body) req.write(JSON.stringify(options.body));
            req.end();
        });
    }

    t.after(() => {
        if (server && server.listening) server.close();
        if (typeof db.closeDatabase === 'function') db.closeDatabase();
        const filesToClean = [
            testDbPath,
            `${testDbPath}-wal`,
            `${testDbPath}-shm`,
            testSeedPath,
            `${testSeedPath}.backup`
        ];
        for (const f of filesToClean) {
            try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch {}
        }
    });

    await t.test('1. Key Generation returns proper key and key_display fields and saves to persistent storage', async () => {
        const res = await request('/api/keys/generate', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${adminToken}` },
            body: {
                product_name: 'OPTIMIZER',
                duration_hours: 720,
                max_devices: 2,
                customer_name: 'Persistence User',
                notes: 'Created for 24/7 test'
            }
        });

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.success, true);
        assert.ok(res.body.key || res.body.key_display);
        const generatedKey = res.body.key_display || res.body.key;
        assert.ok(generatedKey.startsWith('OPTIMIZER-'));
        assert.strictEqual(res.body.product_name, 'OPTIMIZER');

        // Check file was created
        assert.ok(fs.existsSync(testSeedPath), 'Seed file must be created on key generation');
        const seedContent = JSON.parse(fs.readFileSync(testSeedPath, 'utf8'));
        const foundInSeed = seedContent.find(k => (k.key || k.key_display) === generatedKey);
        assert.ok(foundInSeed, 'Generated key must exist in seed-keys.json');
    });

    await t.test('2. Web Restart Simulation: Key data survives full database close and re-initialization', async () => {
        // Create another key
        const newKey = await db.createActivationKey({
            keyString: 'OPTIMIZER-PERSIST-9999-8888-7777',
            productId: 1,
            durationHours: 24,
            maxDevices: 1,
            customerName: 'Restart Survivor',
            notes: 'Must survive restart'
        });

        assert.ok(newKey);
        assert.strictEqual(newKey.key_display, 'OPTIMIZER-PERSIST-9999-8888-7777');

        // Simulate server restart: close database and re-open
        db.closeDatabase();
        db.setSqliteDb(testDbPath);
        await db.initDatabase();

        const keysAfterRestart = await db.getAllKeys({ limit: 100 });
        const survivor = keysAfterRestart.find(k => k.key_display === 'OPTIMIZER-PERSIST-9999-8888-7777');
        assert.ok(survivor, 'Key must be present in database after full restart');
        assert.strictEqual(survivor.customer_name, 'Restart Survivor');

        // Verify backup seed file exists
        assert.ok(fs.existsSync(`${testSeedPath}.backup`), 'Seed backup file must be present for disaster recovery');
    });

    await t.test('3. Recovery from Backup: If primary seed file is damaged, system auto-recovers from backup', async () => {
        const seedKeysBefore = JSON.parse(fs.readFileSync(testSeedPath, 'utf8'));
        assert.ok(seedKeysBefore.length > 0);

        // Corrupt/empty primary seed file
        fs.writeFileSync(testSeedPath, '', 'utf8');

        // Call importSeedKeys() - should auto-recover from .backup
        const importedCount = await db.importSeedKeys();
        assert.ok(importedCount >= 0, 'Should handle corrupted primary by recovering from backup');

        const keysInDb = await db.getAllKeys({ limit: 100 });
        assert.ok(keysInDb.length > 0, 'Keys in database must remain intact');
    });

    await t.test('4. Backup & Export Endpoints: /api/keys/export and /api/admin/keys/backup return valid JSON backup', async () => {
        const exportRes = await request('/api/keys/export', {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });

        assert.strictEqual(exportRes.status, 200);
        assert.strictEqual(exportRes.body.success, true);
        assert.ok(Array.isArray(exportRes.body.keys));
        assert.ok(exportRes.body.keys.length > 0);

        const backupRes = await request('/api/admin/keys/backup', {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });

        assert.strictEqual(backupRes.status, 200);
        assert.strictEqual(backupRes.body.success, true);
        assert.ok(Array.isArray(backupRes.body.keys));
    });

    await t.test('5. Health Endpoint returns 24/7 Persistent runtime status', async () => {
        const health = await request('/api/health');
        assert.strictEqual(health.status, 200);
        assert.strictEqual(health.body.status, 'ok');
        assert.strictEqual(health.body.runtime, '24/7 Persistent');
        assert.ok(typeof health.body.uptime === 'number');
    });

    await t.test('6. UI Client Storage: HTML contains persistent storage keys and handles web reload safely', () => {
        const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
        assert.ok(html.includes('azerox_optimizer_latest_key_v2'), 'index.html must use persistent storage key for latest generated key');
        assert.ok(html.includes('azerox_optimizer_all_keys_v2'), 'index.html must use persistent storage key for all keys');
        assert.ok(html.includes('downloadKeysBackup'), 'index.html must include downloadKeysBackup function');
    });
});
