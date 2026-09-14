import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';

const { Pool } = pg;

describe('PostgreSQL identity tenant isolation', { skip: !process.env.TEST_DATABASE_URL }, () => {
  it('isolates users and memberships by organization tenant context', async () => {
    const pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
    const suffix = Date.now().toString();
    const orgA = `identity_test_a_${suffix}`;
    const orgB = `identity_test_b_${suffix}`;
    const userA = `identity_user_a_${suffix}`;
    const userB = `identity_user_b_${suffix}`;
    const membershipA = `identity_membership_a_${suffix}`;
    const membershipB = `identity_membership_b_${suffix}`;

    try {
      await pool.query(
        `INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3), ($4, $5, $6)`,
        [orgA, orgA, 'Identity Test A', orgB, orgB, 'Identity Test B']
      );

      const insertTenantData = async (organizationId: string, userId: string, membershipId: string, email: string) => {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [organizationId]);
          await client.query(
            `INSERT INTO users (id, organization_id, email, full_name, role)
             VALUES ($1, $2, $3, $4, 'STUDENT')`,
            [userId, organizationId, email, userId]
          );
          await client.query(
            `INSERT INTO organization_memberships (id, user_id, organization_id, role)
             VALUES ($1, $2, $3, 'STUDENT')`,
            [membershipId, userId, organizationId]
          );
          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK').catch(() => {});
          throw error;
        } finally {
          client.release();
        }
      };

      await insertTenantData(orgA, userA, membershipA, `${userA}@example.test`);
      await insertTenantData(orgB, userB, membershipB, `${userB}@example.test`);

      const readTenant = async (organizationId: string) => {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [organizationId]);
          const users = await client.query('SELECT id FROM users ORDER BY id');
          const memberships = await client.query('SELECT id FROM organization_memberships ORDER BY id');
          await client.query('ROLLBACK');
          return {
            users: users.rows.map((row) => row.id),
            memberships: memberships.rows.map((row) => row.id),
          };
        } finally {
          client.release();
        }
      };

      assert.deepEqual(await readTenant(orgA), { users: [userA], memberships: [membershipA] });
      assert.deepEqual(await readTenant(orgB), { users: [userB], memberships: [membershipB] });
    } finally {
      await pool.query('DELETE FROM organizations WHERE id IN ($1, $2)', [orgA, orgB]);
      await pool.end();
    }
  });
});
