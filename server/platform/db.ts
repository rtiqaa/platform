import crypto from 'node:crypto';
import type {
  Organization,
  User,
  AcademicYear,
  Term,
  GradeLevel,
  Classroom,
  Subject,
  Course,
  Lesson,
  Assignment,
  Submission,
  AttendanceRecord,
  AttendanceSession,
  AttendanceSessionStatus,
  Assessment,
  AssessmentCategory,
  AssessmentStatus,
  AssessmentGrade,
  StudentAssessmentItem,
  StudentCoursePerformance,
  StudentAcademicPerformanceSummary,
  GradebookMatrix,
  GradebookMatrixRow,
  GradebookMatrixStudentScore,
  AuditLog,
  Invitation,
  OrganizationMembership,
  StudentProfile,
  ParentLinkToken,
  PasswordResetToken,
  EmailVerificationToken,
  PhoneVerificationOtp,
  AuthProviderType,
  AIConversation,
  AIMessage,
  AIUsageRecord,
  AIDocumentChunk,
  AIUsageSummary,
  TeacherAssignment,
  StudentEnrollment,
  ParentStudentLink,
  TeacherAssignmentRole,
  StudentEnrollmentStatus,
  StudentRecord,
  StudentBehaviorRecord,
  StudentLifecycleEvent,
  StudentDossier,
  StudentLifecycleStatus,
  StudentBehaviorType,
  StudentGender,
  StudentBloodType,
  StorageObjectMetadata,
  StorageResourceType,
  StorageObjectStatus,
  NotificationItem,
  NotificationType,
  NotificationChannel,
  CurriculumUnit,
  LibraryResource,
  ResourceActivity,
  LibraryStats,
  LibraryResourceType,
  LibraryResourceVisibility,
  LibraryResourceStatus,
  ResourceActivityAction,
} from './types.ts';
import { checkPostgresConnection, getPostgresPool, queryGlobal, withTenantClient } from '../../src/db/postgres.ts';
import type { PostgresStatus } from '../../src/db/postgres.ts';
import { hashPassword } from './security.ts';

// In-Memory & PostgreSQL Dual Storage Engine

const generateId = (prefix: string) => `${prefix}_${crypto.randomUUID().replace(/-/g, '').substring(0, 16)}`;

class PlatformDatabase {
  private organizations: Map<string, Organization> = new Map();
  private users: Map<string, User> = new Map();
  private academicYears: Map<string, AcademicYear> = new Map();
  private terms: Map<string, Term> = new Map();
  private gradeLevels: Map<string, GradeLevel> = new Map();
  private classrooms: Map<string, Classroom> = new Map();
  private subjects: Map<string, Subject> = new Map();
  private courses: Map<string, Course> = new Map();
  private lessons: Map<string, Lesson> = new Map();
  private assignments: Map<string, Assignment> = new Map();
  private submissions: Map<string, Submission> = new Map();
  private attendanceSessions: Map<string, AttendanceSession> = new Map();
  private attendanceRecords: Map<string, AttendanceRecord> = new Map();
  private assessments: Map<string, Assessment> = new Map();
  private assessmentGrades: Map<string, AssessmentGrade> = new Map();
  private storageObjects: Map<string, StorageObjectMetadata> = new Map();
  private auditLogs: Map<string, AuditLog> = new Map();
  private invitations: Map<string, Invitation> = new Map();
  private organizationMemberships: Map<string, OrganizationMembership> = new Map();
  private studentProfiles: Map<string, StudentProfile> = new Map();
  private parentLinkTokens: Map<string, ParentLinkToken> = new Map();
  private passwordResetTokens: Map<string, PasswordResetToken> = new Map();
  private emailVerificationTokens: Map<string, EmailVerificationToken> = new Map();
  private phoneVerificationOtps: Map<string, PhoneVerificationOtp> = new Map();
  private aiConversations: Map<string, AIConversation> = new Map();
  private aiMessages: Map<string, AIMessage> = new Map();
  private aiUsageRecords: Map<string, AIUsageRecord> = new Map();
  private aiDocumentChunks: Map<string, AIDocumentChunk> = new Map();
  private teacherAssignments: Map<string, TeacherAssignment> = new Map();
  private studentEnrollments: Map<string, StudentEnrollment> = new Map();
  private parentStudentLinks: Map<string, ParentStudentLink> = new Map();
  private studentRecords: Map<string, StudentRecord> = new Map();
  private studentBehaviorRecords: Map<string, StudentBehaviorRecord> = new Map();
  private studentLifecycleEvents: Map<string, StudentLifecycleEvent> = new Map();
  private notifications: Map<string, NotificationItem> = new Map();
  private curriculumUnits: Map<string, CurriculumUnit> = new Map();
  private libraryResources: Map<string, LibraryResource> = new Map();
  private resourceActivities: Map<string, ResourceActivity> = new Map();

  constructor() {
    if (process.env.NODE_ENV !== 'production') {
      this.seedInitialData();
    }
  }

  // --- Engine Status Check ---
  async getEngineStatus(): Promise<PostgresStatus> {
    return checkPostgresConnection();
  }

  private mapOrganizationRow(row: any): Organization {
    return {
      id: row.id,
      slug: row.slug,
      name: row.name,
      legalName: row.legal_name || undefined,
      countryCode: row.country_code,
      timezone: row.timezone,
      locale: row.locale === 'en' ? 'en' : 'ar',
      logoUrl: row.logo_url || undefined,
      isActive: Boolean(row.is_active),
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
      updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  private mapUserRow(row: any): User {
    return {
      id: row.id,
      organizationId: row.organization_id,
      email: row.email,
      passwordHash: row.password_hash || undefined,
      fullName: row.full_name,
      role: row.role,
      avatarUrl: row.avatar_url || undefined,
      phone: row.phone || undefined,
      studentIdNumber: row.student_id_number || undefined,
      teacherSpecialization: row.teacher_specialization || undefined,
      classroomId: row.classroom_id || undefined,
      emailVerified: Boolean(row.email_verified),
      phoneVerified: Boolean(row.phone_verified),
      authProviders: row.auth_providers || ['email'],
      googleId: row.google_id || undefined,
      isActive: Boolean(row.is_active),
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
      updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  private mapMembershipRow(row: any, organization?: Organization): OrganizationMembership {
    return {
      id: row.id,
      userId: row.user_id,
      organizationId: row.organization_id,
      role: row.role,
      isDefault: Boolean(row.is_default),
      status: row.status,
      classroomId: row.classroom_id || undefined,
      studentIdNumber: row.student_id_number || undefined,
      teacherSpecialization: row.teacher_specialization || undefined,
      organizationName: organization?.name,
      organizationSlug: organization?.slug,
      joinedAt: row.joined_at?.toISOString ? row.joined_at.toISOString() : String(row.joined_at),
    };
  }

  private async getProductionOrganizationIds(): Promise<string[]> {
    const result = await queryGlobal<{ id: string }>(
      'SELECT id FROM organizations WHERE is_active = TRUE ORDER BY id'
    );
    return result.rows.map((row) => row.id);
  }

  private async withIdentityTenant<T>(organizationId: string, callback: (client: any) => Promise<T>): Promise<T> {
    if (!organizationId) throw new Error('TENANT_REQUIRED');
    return withTenantClient(organizationId, callback);
  }

  async getOrganizationByIdAsync(organizationId: string): Promise<Organization | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getOrganizationById(organizationId);
    const result = await queryGlobal(
      `SELECT id, slug, name, legal_name, country_code, timezone, locale, logo_url,
              is_active, created_at, updated_at
       FROM organizations WHERE id = $1 AND is_active = TRUE`,
      [organizationId]
    );
    return result.rows[0] ? this.mapOrganizationRow(result.rows[0]) : undefined;
  }

  async getOrganizationBySlugAsync(slug: string): Promise<Organization | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getOrganizationBySlug(slug);
    const result = await queryGlobal(
      `SELECT id, slug, name, legal_name, country_code, timezone, locale, logo_url,
              is_active, created_at, updated_at
       FROM organizations WHERE (slug = $1 OR id = $1) AND is_active = TRUE`,
      [slug]
    );
    return result.rows[0] ? this.mapOrganizationRow(result.rows[0]) : undefined;
  }

  async getUsersByOrgAsync(organizationId: string, role?: string): Promise<User[]> {
    if (process.env.NODE_ENV !== 'production') return this.getUsersByOrg(organizationId, role);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `SELECT id, organization_id, email, password_hash, full_name, role, avatar_url,
                phone, student_id_number, teacher_specialization, classroom_id,
                email_verified, phone_verified, auth_providers, google_id, is_active,
                created_at, updated_at
         FROM users
         WHERE organization_id = $1 AND ($2::text IS NULL OR role = $2)
         ORDER BY full_name, id`,
        [organizationId, role || null]
      );
      return result.rows.map((row: any) => this.mapUserRow(row));
    });
  }

  async isClassroomInOrgAsync(classroomId: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.isClassroomInOrg(classroomId, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        'SELECT 1 FROM classrooms WHERE id = $1 AND organization_id = $2 LIMIT 1',
        [classroomId, organizationId]
      );
      return result.rowCount === 1;
    });
  }

  async getUserByIdAsync(userId: string, organizationId?: string): Promise<User | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getUserById(userId, organizationId);
    const organizationIds = organizationId ? [organizationId] : await this.getProductionOrganizationIds();
    for (const currentOrganizationId of organizationIds) {
      const user = await this.withIdentityTenant(currentOrganizationId, async (client) => {
        const result = await client.query(
          `SELECT id, organization_id, email, password_hash, full_name, role, avatar_url,
                  phone, student_id_number, teacher_specialization, classroom_id,
                  email_verified, phone_verified, auth_providers, google_id, is_active,
                  created_at, updated_at
           FROM users WHERE id = $1 AND organization_id = $2`,
          [userId, currentOrganizationId]
        );
        return result.rows[0] ? this.mapUserRow(result.rows[0]) : undefined;
      });
      if (user) return user;
    }
    return undefined;
  }

  async findUserByEmailAsync(email: string, organizationId?: string): Promise<User | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.findUserByEmail(email, organizationId);
    const normalized = email.trim().toLowerCase();
    const organizationIds = organizationId ? [organizationId] : await this.getProductionOrganizationIds();
    for (const currentOrganizationId of organizationIds) {
      const user = await this.withIdentityTenant(currentOrganizationId, async (client) => {
        const result = await client.query(
          `SELECT id, organization_id, email, password_hash, full_name, role, avatar_url,
                  phone, student_id_number, teacher_specialization, classroom_id,
                  email_verified, phone_verified, auth_providers, google_id, is_active,
                  created_at, updated_at
           FROM users WHERE lower(email) = $1 AND organization_id = $2`,
          [normalized, currentOrganizationId]
        );
        return result.rows[0] ? this.mapUserRow(result.rows[0]) : undefined;
      });
      if (user) return user;
    }
    return undefined;
  }

  async findUserByPhoneAsync(phone: string, organizationId?: string): Promise<User | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.findUserByPhone(phone, organizationId);
    const organizationIds = organizationId ? [organizationId] : await this.getProductionOrganizationIds();
    for (const currentOrganizationId of organizationIds) {
      const user = await this.withIdentityTenant(currentOrganizationId, async (client) => {
        const result = await client.query(
          `SELECT id, organization_id, email, password_hash, full_name, role, avatar_url,
                  phone, student_id_number, teacher_specialization, classroom_id,
                  email_verified, phone_verified, auth_providers, google_id, is_active,
                  created_at, updated_at
           FROM users WHERE phone = $1 AND organization_id = $2`,
          [phone.trim(), currentOrganizationId]
        );
        return result.rows[0] ? this.mapUserRow(result.rows[0]) : undefined;
      });
      if (user) return user;
    }
    return undefined;
  }

  async findUserByGoogleIdAsync(googleId: string): Promise<User | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.findUserByGoogleId(googleId);
    const organizationIds = await this.getProductionOrganizationIds();
    for (const organizationId of organizationIds) {
      const user = await this.withIdentityTenant(organizationId, async (client) => {
        const result = await client.query(
          `SELECT id, organization_id, email, password_hash, full_name, role, avatar_url,
                  phone, student_id_number, teacher_specialization, classroom_id,
                  email_verified, phone_verified, auth_providers, google_id, is_active,
                  created_at, updated_at
           FROM users WHERE google_id = $1 AND organization_id = $2`,
          [googleId.trim(), organizationId]
        );
        return result.rows[0] ? this.mapUserRow(result.rows[0]) : undefined;
      });
      if (user) return user;
    }
    return undefined;
  }

  async getMembershipsByUserIdAsync(userId: string): Promise<OrganizationMembership[]> {
    if (process.env.NODE_ENV !== 'production') return this.getMembershipsByUserId(userId);
    const memberships: OrganizationMembership[] = [];
    for (const organizationId of await this.getProductionOrganizationIds()) {
      const organization = await this.getOrganizationByIdAsync(organizationId);
      const rows = await this.withIdentityTenant(organizationId, async (client) => {
        const result = await client.query(
          `SELECT id, user_id, organization_id, role, is_default, status, classroom_id,
                  student_id_number, teacher_specialization, joined_at
           FROM organization_memberships
           WHERE user_id = $1 AND organization_id = $2 AND status <> 'REVOKED'`,
          [userId, organizationId]
        );
        return result.rows;
      });
      memberships.push(...rows.map((row: any) => this.mapMembershipRow(row, organization)));
    }
    return memberships;
  }

  async getMembershipByIdAsync(membershipId: string): Promise<OrganizationMembership | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getMembershipById(membershipId);
    for (const organizationId of await this.getProductionOrganizationIds()) {
      const organization = await this.getOrganizationByIdAsync(organizationId);
      const membership = await this.withIdentityTenant(organizationId, async (client) => {
        const result = await client.query(
          `SELECT id, user_id, organization_id, role, is_default, status, classroom_id,
                  student_id_number, teacher_specialization, joined_at
           FROM organization_memberships
           WHERE id = $1 AND organization_id = $2 AND status <> 'REVOKED'`,
          [membershipId, organizationId]
        );
        return result.rows[0] ? this.mapMembershipRow(result.rows[0], organization) : undefined;
      });
      if (membership) return membership;
    }
    return undefined;
  }

  async getMembershipAsync(userId: string, organizationId: string): Promise<OrganizationMembership | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getMembership(userId, organizationId);
    const organization = await this.getOrganizationByIdAsync(organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `SELECT id, user_id, organization_id, role, is_default, status, classroom_id,
                student_id_number, teacher_specialization, joined_at
         FROM organization_memberships
         WHERE user_id = $1 AND organization_id = $2 AND status <> 'REVOKED'`,
        [userId, organizationId]
      );
      return result.rows[0] ? this.mapMembershipRow(result.rows[0], organization) : undefined;
    });
  }

  async createOrganizationAsync(data: Omit<Organization, 'id' | 'createdAt' | 'updatedAt'>): Promise<Organization> {
    if (process.env.NODE_ENV !== 'production') return this.createOrganization(data);
    const id = generateId('org');
    const now = new Date();
    const result = await queryGlobal(
      `INSERT INTO organizations (
         id, slug, name, legal_name, country_code, timezone, locale, logo_url, is_active, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
       RETURNING id, slug, name, legal_name, country_code, timezone, locale, logo_url, is_active, created_at, updated_at`,
      [id, data.slug, data.name, data.legalName || null, data.countryCode, data.timezone, data.locale, data.logoUrl || null, data.isActive, now]
    );
    return this.mapOrganizationRow(result.rows[0]);
  }

  async createUserAsync(data: Omit<User, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }): Promise<User> {
    if (process.env.NODE_ENV !== 'production') return this.createUser(data);
    if (!data.organizationId) throw new Error('TENANT_REQUIRED');
    const id = data.id || generateId('usr');
    const now = new Date();
    const user = await this.withIdentityTenant(data.organizationId, async (client) => {
      await client.query('BEGIN');
      try {
        const result = await client.query(
          `INSERT INTO users (
             id, organization_id, email, password_hash, full_name, role, avatar_url, phone,
             student_id_number, teacher_specialization, classroom_id, email_verified,
             phone_verified, auth_providers, google_id, is_active, created_at, updated_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $17)
           RETURNING id, organization_id, email, password_hash, full_name, role, avatar_url, phone,
                     student_id_number, teacher_specialization, classroom_id, email_verified,
                     phone_verified, auth_providers, google_id, is_active, created_at, updated_at`,
          [
            id,
            data.organizationId,
            data.email.trim().toLowerCase(),
            data.passwordHash || null,
            data.fullName,
            data.role,
            data.avatarUrl || null,
            data.phone || null,
            data.studentIdNumber || null,
            data.teacherSpecialization || null,
            data.classroomId || null,
            data.emailVerified ?? false,
            data.phoneVerified ?? false,
            JSON.stringify(data.authProviders || ['email']),
            data.googleId || null,
            data.isActive,
            now,
          ]
        );
        const membershipId = generateId('mem');
        await client.query(
          `INSERT INTO organization_memberships (
             id, user_id, organization_id, role, is_default, status, classroom_id,
             student_id_number, teacher_specialization, joined_at
           ) VALUES ($1, $2, $3, $4, TRUE, 'ACTIVE', $5, $6, $7, $8)`,
          [membershipId, id, data.organizationId, data.role, data.classroomId || null, data.studentIdNumber || null, data.teacherSpecialization || null, now]
        );
        await client.query('COMMIT');
        return this.mapUserRow(result.rows[0]);
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      }
    });
    return user;
  }

  async updateUserAsync(id: string, organizationId: string, updates: Partial<User>): Promise<User | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateUser(id, organizationId, updates);
    const allowed: Array<[string, unknown]> = [
      ['email', updates.email?.trim().toLowerCase()],
      ['password_hash', updates.passwordHash],
      ['full_name', updates.fullName],
      ['role', updates.role],
      ['avatar_url', updates.avatarUrl],
      ['phone', updates.phone],
      ['student_id_number', updates.studentIdNumber],
      ['teacher_specialization', updates.teacherSpecialization],
      ['classroom_id', updates.classroomId],
      ['email_verified', updates.emailVerified],
      ['phone_verified', updates.phoneVerified],
      ['auth_providers', updates.authProviders ? JSON.stringify(updates.authProviders) : undefined],
      ['google_id', updates.googleId],
      ['is_active', updates.isActive],
    ].filter(([, value]) => value !== undefined) as Array<[string, unknown]>;
    if (allowed.length === 0) return this.getUserByIdAsync(id, organizationId);

    return this.withIdentityTenant(organizationId, async (client) => {
      const setClause = allowed.map(([column], index) => `${column} = $${index + 3}`).join(', ');
      const values = allowed.map(([, value]) => value);
      const result = await client.query(
        `UPDATE users SET ${setClause}, updated_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND organization_id = $2
         RETURNING id, organization_id, email, password_hash, full_name, role, avatar_url, phone,
                   student_id_number, teacher_specialization, classroom_id, email_verified,
                   phone_verified, auth_providers, google_id, is_active, created_at, updated_at`,
        [id, organizationId, ...values]
      );
      return result.rows[0] ? this.mapUserRow(result.rows[0]) : undefined;
    });
  }

  async unlinkAccountProviderAsync(
    userId: string,
    organizationId: string,
    provider: AuthProviderType
  ): Promise<{ success: boolean; user?: User; error?: string }> {
    if (process.env.NODE_ENV !== 'production') return this.unlinkAccountProvider(userId, provider);
    const user = await this.getUserByIdAsync(userId, organizationId);
    if (!user) return { success: false, error: 'USER_NOT_FOUND' };
    const providers = user.authProviders || ['email'];
    if (providers.length <= 1) return { success: false, error: 'CANNOT_UNLINK_LAST_PROVIDER', user };
    const updates: Partial<User> = {
      authProviders: providers.filter((current) => current !== provider),
    };
    if (provider === 'google') updates.googleId = undefined;
    if (provider === 'phone') {
      updates.phone = undefined;
      updates.phoneVerified = false;
    }
    if (provider === 'email') updates.emailVerified = false;
    const updated = await this.updateUserAsync(userId, organizationId, updates);
    return { success: true, user: updated };
  }

  async deleteUserAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteUser(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        'DELETE FROM users WHERE id = $1 AND organization_id = $2 RETURNING id',
        [id, organizationId]
      );
      return result.rowCount === 1;
    });
  }

  async addMembershipAsync(data: Omit<OrganizationMembership, 'id' | 'joinedAt'>): Promise<OrganizationMembership> {
    if (process.env.NODE_ENV !== 'production') return this.addMembership(data);
    const id = generateId('mem');
    return this.withIdentityTenant(data.organizationId, async (client) => {
      const result = await client.query(
        `INSERT INTO organization_memberships (
           id, user_id, organization_id, role, is_default, status, classroom_id,
           student_id_number, teacher_specialization, joined_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
         RETURNING id, user_id, organization_id, role, is_default, status, classroom_id,
                   student_id_number, teacher_specialization, joined_at`,
        [id, data.userId, data.organizationId, data.role, data.isDefault, data.status, data.classroomId || null, data.studentIdNumber || null, data.teacherSpecialization || null]
      );
      const organization = await this.getOrganizationByIdAsync(data.organizationId);
      return this.mapMembershipRow(result.rows[0], organization);
    });
  }

  async updateMembershipAsync(
    id: string,
    organizationId: string,
    updates: Partial<OrganizationMembership>
  ): Promise<OrganizationMembership | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateMembership(id, updates);
    const allowed: Array<[string, unknown]> = [
      ['role', updates.role],
      ['is_default', updates.isDefault],
      ['status', updates.status],
      ['classroom_id', updates.classroomId],
      ['student_id_number', updates.studentIdNumber],
      ['teacher_specialization', updates.teacherSpecialization],
    ].filter(([, value]) => value !== undefined) as Array<[string, unknown]>;
    if (allowed.length === 0) return this.getMembershipByIdAsync(id);

    return this.withIdentityTenant(organizationId, async (client) => {
      const setClause = allowed.map(([column], index) => `${column} = $${index + 3}`).join(', ');
      const values = allowed.map(([, value]) => value);
      const result = await client.query(
        `UPDATE organization_memberships SET ${setClause}
         WHERE id = $1 AND organization_id = $2
         RETURNING id, user_id, organization_id, role, is_default, status, classroom_id,
                   student_id_number, teacher_specialization, joined_at`,
        [id, organizationId, ...values]
      );
      if (!result.rows[0]) return undefined;
      const organization = await this.getOrganizationByIdAsync(organizationId);
      return this.mapMembershipRow(result.rows[0], organization);
    });
  }

  async removeMembershipAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.removeMembership(id);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `UPDATE organization_memberships SET status = 'REVOKED'
         WHERE id = $1 AND organization_id = $2 AND status <> 'REVOKED'
         RETURNING id`,
        [id, organizationId]
      );
      return result.rowCount === 1;
    });
  }

  /** Loads identity and tenant context from PostgreSQL for the production process. */
  async initializeFromPostgres(): Promise<void> {
    if (process.env.NODE_ENV !== 'production') return;

    const status = await checkPostgresConnection();
    if (!status.connected) {
      throw new Error('POSTGRES_REQUIRED_FOR_PRODUCTION_DATA');
    }

    const organizationResult = await queryGlobal<{
      id: string;
      slug: string;
      name: string;
      legal_name: string | null;
      country_code: string;
      timezone: string;
      locale: string;
      logo_url: string | null;
      is_active: boolean;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT id, slug, name, legal_name, country_code, timezone, locale, logo_url,
              is_active, created_at, updated_at
       FROM organizations
       WHERE is_active = TRUE
       ORDER BY id`
    );

    for (const row of organizationResult.rows) {
      const organization: Organization = {
        id: row.id,
        slug: row.slug,
        name: row.name,
        legalName: row.legal_name || undefined,
        countryCode: row.country_code,
        timezone: row.timezone,
        locale: row.locale === 'en' ? 'en' : 'ar',
        logoUrl: row.logo_url || undefined,
        isActive: row.is_active,
        createdAt: row.created_at.toISOString(),
        updatedAt: row.updated_at.toISOString(),
      };
      this.organizations.set(organization.id, organization);

      await withTenantClient(organization.id, async (client) => {
        const [usersResult, membershipsResult] = await Promise.all([
          client.query(`
            SELECT id, organization_id, email, password_hash, full_name, role, avatar_url,
                   phone, student_id_number, teacher_specialization, classroom_id,
                   email_verified, phone_verified, auth_providers, google_id, is_active,
                   created_at, updated_at
            FROM users
            WHERE organization_id = $1 AND is_active = TRUE`, [organization.id]),
          client.query(`
            SELECT id, user_id, organization_id, role, is_default, status, classroom_id,
                   student_id_number, teacher_specialization, joined_at
            FROM organization_memberships
            WHERE organization_id = $1 AND status <> 'REVOKED'`, [organization.id]),
        ]);

        for (const row of usersResult.rows) {
          const user: User = {
            id: row.id,
            organizationId: row.organization_id,
            email: row.email,
            passwordHash: row.password_hash || undefined,
            fullName: row.full_name,
            role: row.role,
            avatarUrl: row.avatar_url || undefined,
            phone: row.phone || undefined,
            studentIdNumber: row.student_id_number || undefined,
            teacherSpecialization: row.teacher_specialization || undefined,
            classroomId: row.classroom_id || undefined,
            emailVerified: row.email_verified,
            phoneVerified: row.phone_verified,
            authProviders: row.auth_providers || ['email'],
            googleId: row.google_id || undefined,
            isActive: row.is_active,
            createdAt: row.created_at.toISOString(),
            updatedAt: row.updated_at.toISOString(),
          };
          this.users.set(user.id, user);
        }

        for (const row of membershipsResult.rows) {
          const membership: OrganizationMembership = {
            id: row.id,
            userId: row.user_id,
            organizationId: row.organization_id,
            role: row.role,
            isDefault: row.is_default,
            status: row.status,
            classroomId: row.classroom_id || undefined,
            studentIdNumber: row.student_id_number || undefined,
            teacherSpecialization: row.teacher_specialization || undefined,
            joinedAt: row.joined_at.toISOString(),
          };
          this.organizationMemberships.set(membership.id, membership);
        }
      });
    }
  }

  // --- Seed realistic Multi-Tenant Data ---
  private seedInitialData() {
    // 1. School A: Horizon Smart Schools
    const schoolAId = 'org_horizon_001';
    const schoolA: Organization = {
      id: schoolAId,
      slug: 'horizon',
      name: 'مدارس الأفق الذكية (Horizon Smart Schools)',
      legalName: 'شركة مدارس الأفق للتعليم والتربية الذكية',
      countryCode: 'SA',
      timezone: 'Asia/Riyadh',
      locale: 'ar',
      logoUrl: '',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.organizations.set(schoolAId, schoolA);

    // 2. School B: Elite Model Schools (To verify tenant isolation)
    const schoolBId = 'org_elite_002';
    const schoolB: Organization = {
      id: schoolBId,
      slug: 'elite',
      name: 'أكاديمية النخبة الدولية (Elite International Academy)',
      legalName: 'شركة النخبة الدولية للتعليم المتقدم',
      countryCode: 'SA',
      timezone: 'Asia/Riyadh',
      locale: 'ar',
      logoUrl: '',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.organizations.set(schoolBId, schoolB);

    // School A: Academic Year & Term
    const yearAId = 'ay_horizon_2026';
    this.academicYears.set(yearAId, {
      id: yearAId,
      organizationId: schoolAId,
      name: 'العام الدراسي 2026-2027',
      startDate: '2026-08-20',
      endDate: '2027-06-15',
      isCurrent: true,
    });

    const termAId = 'term_horizon_t1';
    this.terms.set(termAId, {
      id: termAId,
      organizationId: schoolAId,
      academicYearId: yearAId,
      name: 'الفصل الدراسي الأول (الخريف)',
      startDate: '2026-08-20',
      endDate: '2026-11-25',
      isCurrent: true,
    });

    const termA2Id = 'term_horizon_t2';
    this.terms.set(termA2Id, {
      id: termA2Id,
      organizationId: schoolAId,
      academicYearId: yearAId,
      name: 'الفصل الدراسي الثاني (الربيع)',
      startDate: '2026-12-05',
      endDate: '2027-03-10',
      isCurrent: false,
    });

    // School A: Grade Level & Classrooms
    const grade10Id = 'grd_horizon_g10';
    this.gradeLevels.set(grade10Id, {
      id: grade10Id,
      organizationId: schoolAId,
      name: 'الصف العاشر (الأول ثانوي)',
      sequenceOrder: 10,
    });

    const grade11Id = 'grd_horizon_g11';
    this.gradeLevels.set(grade11Id, {
      id: grade11Id,
      organizationId: schoolAId,
      name: 'الصف الحادي عشر (الثاني ثانوي)',
      sequenceOrder: 11,
    });

    const class10AId = 'class_horizon_10a';
    this.classrooms.set(class10AId, {
      id: class10AId,
      organizationId: schoolAId,
      gradeLevelId: grade10Id,
      name: 'شعبة 10-أ (علمي)',
      capacity: 32,
    });

    const class10BId = 'class_horizon_10b';
    this.classrooms.set(class10BId, {
      id: class10BId,
      organizationId: schoolAId,
      gradeLevelId: grade10Id,
      name: 'شعبة 10-ب (عام)',
      capacity: 30,
    });

    // School A: Subjects
    const mathSubId = 'sub_horizon_math';
    this.subjects.set(mathSubId, {
      id: mathSubId,
      organizationId: schoolAId,
      name: 'الرياضيات العامة والتحليل',
      code: 'MATH-101',
      color: '#10b981',
      description: 'منهج الجبر، التفاضل والتكامل للمرحلة الثانوية',
    });

    const physicsSubId = 'sub_horizon_phys';
    this.subjects.set(physicsSubId, {
      id: physicsSubId,
      organizationId: schoolAId,
      name: 'الفيزياء التجريبية والميكانيكا',
      code: 'PHYS-101',
      color: '#3b82f6',
      description: 'قوانين الحركة والميكانيكا الكلاسيكية',
    });

    const arabicSubId = 'sub_horizon_arab';
    this.subjects.set(arabicSubId, {
      id: arabicSubId,
      organizationId: schoolAId,
      name: 'اللغة العربية والأدب',
      code: 'ARAB-101',
      color: '#f59e0b',
      description: 'البلاغة، النحو، وقراءة النصوص التراثية',
    });

    // School A: Users (Admin, 2 Teachers, 4 Students)
    const adminA: User = {
      id: 'usr_horizon_admin',
      organizationId: schoolAId,
      email: 'admin@horizon.edu.sa',
      fullName: 'د. عبد الله المنصور (مدير المدرسة)',
      role: 'ORG_ADMIN',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(adminA.id, adminA);

    const teacherMath: User = {
      id: 'usr_horizon_teacher',
      organizationId: schoolAId,
      email: 'teacher@horizon.edu.sa',
      fullName: 'أ. أحمد الشمري (معلم الرياضيات)',
      role: 'TEACHER',
      teacherSpecialization: 'الرياضيات والفيزياء المتقدمة',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(teacherMath.id, teacherMath);

    const teacherArabic: User = {
      id: 'usr_horizon_t_sarah',
      organizationId: schoolAId,
      email: 'teacher2@horizon.edu.sa',
      fullName: 'أ. سارة الغامدي (معلمة اللغة العربية)',
      role: 'TEACHER',
      teacherSpecialization: 'اللغة العربية والبلاغة',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(teacherArabic.id, teacherArabic);

    const student1: User = {
      id: 'usr_horizon_s_omar',
      organizationId: schoolAId,
      email: 'student@horizon.edu.sa',
      fullName: 'عمر خالد السعيد',
      role: 'STUDENT',
      studentIdNumber: 'STD-2026-001',
      classroomId: class10AId,
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(student1.id, student1);

    const student2: User = {
      id: 'usr_horizon_s_noura',
      organizationId: schoolAId,
      email: 'student2@horizon.edu.sa',
      fullName: 'نورة العتيبي',
      role: 'STUDENT',
      studentIdNumber: 'STD-2026-002',
      classroomId: class10AId,
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(student2.id, student2);

    const student3: User = {
      id: 'usr_horizon_s_faisal',
      organizationId: schoolAId,
      email: 'faisal.m@horizon.edu.sa',
      fullName: 'فيصل المطيري',
      role: 'STUDENT',
      studentIdNumber: 'STD-2026-003',
      classroomId: class10AId,
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(student3.id, student3);

    const student4: User = {
      id: 'usr_horizon_s_reem',
      organizationId: schoolAId,
      email: 'reem.k@horizon.edu.sa',
      fullName: 'ريم القحطاني',
      role: 'STUDENT',
      studentIdNumber: 'STD-2026-004',
      classroomId: class10BId,
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(student4.id, student4);

    const parent1: User = {
      id: 'usr_horizon_p_khalid',
      organizationId: schoolAId,
      email: 'parent@horizon.edu.sa',
      fullName: 'خالد السعيد (ولي أمر)',
      role: 'PARENT',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(parent1.id, parent1);

    // School A: Courses
    const courseMath10AId = 'crs_horizon_math_10a';
    this.courses.set(courseMath10AId, {
      id: courseMath10AId,
      organizationId: schoolAId,
      subjectId: mathSubId,
      termId: termAId,
      teacherId: teacherMath.id,
      classroomId: class10AId,
      title: 'الرياضيات - الصف العاشر (شعبة أ)',
      description: 'شرح شامل للمصفوفات والدوال اللوغاريتمية وحساب المثلثات',
      subjectName: 'الرياضيات العامة والتحليل',
      teacherName: teacherMath.fullName,
      classroomName: 'شعبة 10-أ (علمي)',
    });

    const coursePhy10AId = 'crs_horizon_phys_10a';
    this.courses.set(coursePhy10AId, {
      id: coursePhy10AId,
      organizationId: schoolAId,
      subjectId: physicsSubId,
      termId: termAId,
      teacherId: teacherMath.id,
      classroomId: class10AId,
      title: 'الفيزياء - الصف العاشر (شعبة أ)',
      description: 'مقرر الفيزياء التفاعلي والتجارب المعملية الرقمية',
      subjectName: 'الفيزياء التجريبية والميكانيكا',
      teacherName: teacherMath.fullName,
      classroomName: 'شعبة 10-أ (علمي)',
    });

    const courseArabic10AId = 'crs_horizon_arab_10a';
    this.courses.set(courseArabic10AId, {
      id: courseArabic10AId,
      organizationId: schoolAId,
      subjectId: arabicSubId,
      termId: termAId,
      teacherId: teacherArabic.id,
      classroomId: class10AId,
      title: 'اللغة العربية والبلاغة - الصف العاشر (شعبة أ)',
      description: 'مقرر اللغة العربية والأدب والبلاغة والنقد',
      subjectName: 'اللغة العربية والأدب',
      teacherName: teacherArabic.fullName,
      classroomName: 'شعبة 10-أ (علمي)',
    });

    // School A: Lessons
    const lesson1Id = 'lsn_horizon_math_01';
    this.lessons.set(lesson1Id, {
      id: lesson1Id,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      title: 'مقدمة في الدوال الأسية واللوغاريتمات',
      contentHtml: `
        <h3>مقدمة في الدوال الأسية</h3>
        <p>في هذا الدرس سنتعرف على خصائص الدوال الأسية، كيفية تحويل المعادلات الأسية إلى لوغاريتمية، وتطبيقاتها في النمو السكاني والحسابات المالية.</p>
        <h4>الأهداف التعليمية للدرس:</h4>
        <ul>
          <li>فهم المفهوم الهندسي لميل الخط المستقيم ومعدل التغير.</li>
          <li>تمثيل المعادلات الخطية بيانياً على المستوى الإحداثي.</li>
          <li>حل أنظمة المعادلات الخطية بطريقة الحذف والتعويض.</li>
        </ul>
      `,
      mediaUrl: 'https://images.unsplash.com/photo-1635070041078-e363dbe005cb?w=1200&auto=format&fit=crop&q=80',
      attachments: [
        { name: 'ملخص_الدوال_الخطية.pdf', url: '#', size: '1.4 MB' },
        { name: 'تمارين_تطبيقية_محلولة.pdf', url: '#', size: '850 KB' },
      ],
      orderIndex: 1,
      isPublished: true,
      createdAt: '2026-09-02T08:00:00Z',
      updatedAt: '2026-09-02T08:00:00Z',
    });

    const lesson2Id = 'lsn_horizon_math_02';
    this.lessons.set(lesson2Id, {
      id: lesson2Id,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      title: 'المصفوفات والعمليات الجبرية الخطية',
      contentHtml: `
        <h3>المصفوفات وتطبيقاتها في الحوسبة</h3>
        <p>المصفوفة هي جدول مستطيل من الأعداد مرتبة في صفوف وأعمدة. تُستخدم المصفوفات كأساس لمعالجة الصور وخوارزميات الذكاء الاصطناعي.</p>
      `,
      orderIndex: 2,
      isPublished: true,
      createdAt: '2026-09-09T08:00:00Z',
      updatedAt: '2026-09-09T08:00:00Z',
    });

    // School A: Assignments
    const assign1Id = 'asg_horizon_math_01';
    this.assignments.set(assign1Id, {
      id: assign1Id,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      title: 'الواجب الأول: حل معادلات اللوغاريتمات المركبة',
      description: 'حل المسائل من 1 إلى 8 في صفحة 42، مع كتابة خطوات التحويل والتبسيط كاملة.',
      maxScore: 20,
      dueDate: '2026-10-15T23:59:00Z',
      createdAt: '2026-09-03T10:00:00Z',
    });

    const assign2Id = 'asg_horizon_math_02';
    this.assignments.set(assign2Id, {
      id: assign2Id,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      title: 'المهمة الأدائية: ضرب المصفوفات والتطبيقات الواقعية',
      description: 'تصميم مسألة واقعية وتطبيق مصفوفة 3x3 لحلها.',
      maxScore: 30,
      dueDate: '2026-10-30T23:59:00Z',
      createdAt: '2026-09-10T10:00:00Z',
    });

    // School A: Submissions & Grades
    const sub1Id = 'sub_omar_01';
    this.submissions.set(sub1Id, {
      id: sub1Id,
      organizationId: schoolAId,
      assignmentId: assign1Id,
      studentId: student1.id,
      studentName: student1.fullName,
      submissionText: 'تم حل جميع المسائل الثمانية وتدوين خطوات التحويل بالتفصيل في المرفق.',
      fileAttachmentUrl: 'حل_عمر_السعيد_رياضيات.pdf',
      score: 19.5,
      teacherFeedback: 'إجابة نموذجية ومنظمة جداً يا عمر. أحسنت!',
      submittedAt: '2026-10-14T15:30:00Z',
      gradedAt: '2026-10-15T10:00:00Z',
    });

    const sub2Id = 'sub_noura_01';
    this.submissions.set(sub2Id, {
      id: sub2Id,
      organizationId: schoolAId,
      assignmentId: assign1Id,
      studentId: student2.id,
      studentName: student2.fullName,
      submissionText: 'مرفق حلول المعادلات الستة الأولى والمسألة الإضافية.',
      fileAttachmentUrl: 'حل_نورة_الفهد_رياضيات.pdf',
      score: 18.0,
      teacherFeedback: 'عمل ممتاز، راجعي فقط إشارة الحد الأخير في المسألة 5.',
      submittedAt: '2026-10-14T18:45:00Z',
      gradedAt: '2026-10-15T11:20:00Z',
    });

    // School A: Attendance Records
    const today = new Date().toISOString().split('T')[0];
    this.attendanceRecords.set(`att_${courseMath10AId}_${student1.id}_${today}`, {
      id: `att_${courseMath10AId}_${student1.id}_${today}`,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      classroomId: class10AId,
      studentId: student1.id,
      studentName: student1.fullName,
      recordedBy: teacherMath.id,
      date: today,
      status: 'PRESENT',
      createdAt: new Date().toISOString(),
    });

    this.attendanceRecords.set(`att_${courseMath10AId}_${student2.id}_${today}`, {
      id: `att_${courseMath10AId}_${student2.id}_${today}`,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      classroomId: class10AId,
      studentId: student2.id,
      studentName: student2.fullName,
      recordedBy: teacherMath.id,
      date: today,
      status: 'PRESENT',
      createdAt: new Date().toISOString(),
    });

    this.attendanceRecords.set(`att_${courseMath10AId}_${student3.id}_${today}`, {
      id: `att_${courseMath10AId}_${student3.id}_${today}`,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      classroomId: class10AId,
      studentId: student3.id,
      studentName: student3.fullName,
      recordedBy: teacherMath.id,
      date: today,
      status: 'LATE',
      notes: 'تأخر 10 دقائق بعذر مقبول',
      createdAt: new Date().toISOString(),
    });

    // --- School B: Elite Model Schools (Isolated Tenant) ---
    const adminB: User = {
      id: 'usr_elite_admin',
      organizationId: schoolBId,
      email: 'admin@elite.edu.sa',
      fullName: 'Dr. Sarah Jenkins (Elite Admin)',
      role: 'ORG_ADMIN',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(adminB.id, adminB);

    const teacherB: User = {
      id: 'usr_elite_teacher',
      organizationId: schoolBId,
      email: 'teacher.sara@elite.edu.sa',
      fullName: 'Prof. Marcus Vance (Elite Teacher)',
      role: 'TEACHER',
      teacherSpecialization: 'Advanced Physics & AI',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(teacherB.id, teacherB);

    const studentB: User = {
      id: 'usr_elite_student',
      organizationId: schoolBId,
      email: 'student@elite.edu.sa',
      fullName: 'Zaid Al-Harbi (Elite Student)',
      role: 'STUDENT',
      studentIdNumber: 'ELT-2026-099',
      isActive: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.users.set(studentB.id, studentB);

    // School B: Academic Structure & Courses
    const yearBId = 'year_elite_1448';
    this.academicYears.set(yearBId, {
      id: yearBId,
      organizationId: schoolBId,
      name: 'Academic Year 2026-2027 (1448H)',
      startDate: '2026-09-01',
      endDate: '2027-06-30',
      isCurrent: true,
    });

    const termBId = 'term_elite_t1';
    this.terms.set(termBId, {
      id: termBId,
      organizationId: schoolBId,
      academicYearId: yearBId,
      name: 'Trimester 1',
      startDate: '2026-09-01',
      endDate: '2026-11-30',
      isCurrent: true,
    });

    const gradeBId = 'grd_elite_10';
    this.gradeLevels.set(gradeBId, {
      id: gradeBId,
      organizationId: schoolBId,
      name: 'Grade 10 (Advanced)',
      sequenceOrder: 10,
    });

    const classBId = 'cls_elite_10a';
    this.classrooms.set(classBId, {
      id: classBId,
      organizationId: schoolBId,
      gradeLevelId: gradeBId,
      name: 'Section 10-Alpha',
      capacity: 25,
    });

    const physSubId = 'sbj_elite_phys';
    this.subjects.set(physSubId, {
      id: physSubId,
      organizationId: schoolBId,
      name: 'Advanced Physics',
      code: 'PHY-101',
    });

    const coursePhys10AId = 'crs_elite_phys_10a';
    this.courses.set(coursePhys10AId, {
      id: coursePhys10AId,
      organizationId: schoolBId,
      subjectId: physSubId,
      termId: termBId,
      teacherId: teacherB.id,
      classroomId: classBId,
      title: 'Advanced Physics - Grade 10',
      description: 'Quantum mechanics and classical kinematics',
      subjectName: 'Advanced Physics',
      teacherName: teacherB.fullName,
      classroomName: 'Section 10-Alpha',
    });

    // School A: Teacher Assignments
    const taMathAId = 'ta_horizon_math_10a';
    this.teacherAssignments.set(taMathAId, {
      id: taMathAId,
      organizationId: schoolAId,
      teacherId: teacherMath.id,
      teacherName: teacherMath.fullName,
      teacherEmail: teacherMath.email,
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات المتقدمة - الصف العاشر',
      subjectId: mathSubId,
      subjectName: 'الرياضيات العامة والتحليل',
      classroomId: class10AId,
      classroomName: 'شعبة 10-أ (علمي)',
      academicYearId: yearAId,
      academicYearName: 'العام الدراسي 2026-2027',
      role: 'PRIMARY_TEACHER',
      weeklyHours: 5,
      status: 'ACTIVE',
      createdAt: '2026-08-20T00:00:00Z',
      updatedAt: '2026-08-20T00:00:00Z',
    });

    const taArabAId = 'ta_horizon_arab_10a';
    this.teacherAssignments.set(taArabAId, {
      id: taArabAId,
      organizationId: schoolAId,
      teacherId: teacherArabic.id,
      teacherName: teacherArabic.fullName,
      teacherEmail: teacherArabic.email,
      courseId: courseArabic10AId,
      courseTitle: 'اللغة العربية والبلاغة - الصف العاشر',
      subjectId: arabicSubId,
      subjectName: 'اللغة العربية والأدب',
      classroomId: class10AId,
      classroomName: 'شعبة 10-أ (علمي)',
      academicYearId: yearAId,
      academicYearName: 'العام الدراسي 2026-2027',
      role: 'PRIMARY_TEACHER',
      weeklyHours: 4,
      status: 'ACTIVE',
      createdAt: '2026-08-20T00:00:00Z',
      updatedAt: '2026-08-20T00:00:00Z',
    });

    // School A: Student Enrollments
    const studentsListA = [
      { user: student1, roll: '10A-01' },
      { user: student2, roll: '10A-02' },
      { user: student3, roll: '10A-03' },
      { user: student4, roll: '10A-04' },
    ];
    for (const item of studentsListA) {
      const enrId = `enr_horizon_${item.user.id}`;
      this.studentEnrollments.set(enrId, {
        id: enrId,
        organizationId: schoolAId,
        studentId: item.user.id,
        studentName: item.user.fullName,
        studentEmail: item.user.email,
        studentIdNumber: item.user.studentIdNumber,
        classroomId: class10AId,
        classroomName: 'شعبة 10-أ (علمي)',
        gradeLevelId: grade10Id,
        gradeLevelName: 'الصف العاشر (الأول الثانوي)',
        academicYearId: yearAId,
        academicYearName: 'العام الدراسي 2026-2027',
        rollNumber: item.roll,
        status: 'ACTIVE',
        enrolledAt: '2026-08-20T00:00:00Z',
        updatedAt: '2026-08-20T00:00:00Z',
      });
    }

    // School B: Teacher Assignment & Student Enrollment
    const taPhysBId = 'ta_elite_phys_10a';
    this.teacherAssignments.set(taPhysBId, {
      id: taPhysBId,
      organizationId: schoolBId,
      teacherId: teacherB.id,
      teacherName: teacherB.fullName,
      teacherEmail: teacherB.email,
      courseId: coursePhys10AId,
      courseTitle: 'Advanced Physics - Grade 10',
      subjectId: physSubId,
      subjectName: 'Advanced Physics',
      classroomId: classBId,
      classroomName: 'Section 10-Alpha',
      academicYearId: yearBId,
      academicYearName: 'Academic Year 2026-2027 (1448H)',
      role: 'PRIMARY_TEACHER',
      weeklyHours: 6,
      status: 'ACTIVE',
      createdAt: '2026-09-01T00:00:00Z',
      updatedAt: '2026-09-01T00:00:00Z',
    });

    const enrBId = `enr_elite_${studentB.id}`;
    this.studentEnrollments.set(enrBId, {
      id: enrBId,
      organizationId: schoolBId,
      studentId: studentB.id,
      studentName: studentB.fullName,
      studentEmail: studentB.email,
      studentIdNumber: studentB.studentIdNumber,
      classroomId: classBId,
      classroomName: 'Section 10-Alpha',
      gradeLevelId: gradeBId,
      gradeLevelName: 'Grade 10 (Advanced)',
      academicYearId: yearBId,
      academicYearName: 'Academic Year 2026-2027 (1448H)',
      rollNumber: 'ELT-10A-01',
      status: 'ACTIVE',
      enrolledAt: '2026-09-01T00:00:00Z',
      updatedAt: '2026-09-01T00:00:00Z',
    });

    // School A: Student Records (Comprehensive SIS Profiles)
    const stdRec1: StudentRecord = {
      id: `std_rec_${student1.id}`,
      organizationId: schoolAId,
      studentId: student1.id,
      nationalId: '1098765432',
      dateOfBirth: '2010-04-15',
      gender: 'MALE',
      bloodType: 'O+',
      nationality: 'سعودي',
      admissionDate: '2024-09-01',
      status: 'ACTIVE',
      medicalConditions: 'لا توجد حالات مزمنة',
      allergies: 'حساسية خفيفة من الفول السوداني',
      specialDietaryNeeds: 'وجبات خالية من المكسرات',
      emergencyContactName: 'خالد السعيد (الأب)',
      emergencyContactPhone: '+966501234567',
      emergencyContactRelationship: 'FATHER',
      previousSchool: 'مدارس الرواد النموذجية',
      giftedProgram: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.studentRecords.set(stdRec1.id, stdRec1);

    const stdRec2: StudentRecord = {
      id: `std_rec_${student2.id}`,
      organizationId: schoolAId,
      studentId: student2.id,
      nationalId: '1087654321',
      dateOfBirth: '2010-08-22',
      gender: 'FEMALE',
      bloodType: 'A+',
      nationality: 'سعودية',
      admissionDate: '2024-09-01',
      status: 'ACTIVE',
      emergencyContactName: 'فاطمة العتيبي (الأم)',
      emergencyContactPhone: '+966507654321',
      emergencyContactRelationship: 'MOTHER',
      previousSchool: 'مدارس المستقبل الأهلية',
      giftedProgram: false,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.studentRecords.set(stdRec2.id, stdRec2);

    const stdRec3: StudentRecord = {
      id: `std_rec_${student3.id}`,
      organizationId: schoolAId,
      studentId: student3.id,
      nationalId: '1076543210',
      dateOfBirth: '2010-11-03',
      gender: 'MALE',
      bloodType: 'B+',
      nationality: 'سعودي',
      admissionDate: '2024-09-01',
      status: 'ACTIVE',
      medicalConditions: 'ربو تحسسي خفيف عند ممارسة المجهود الشديد',
      allergies: 'غبار الطلع والأتربة',
      emergencyContactName: 'محمد المطيري (الأب)',
      emergencyContactPhone: '+966509988776',
      emergencyContactRelationship: 'FATHER',
      giftedProgram: false,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.studentRecords.set(stdRec3.id, stdRec3);

    const stdRec4: StudentRecord = {
      id: `std_rec_${student4.id}`,
      organizationId: schoolAId,
      studentId: student4.id,
      nationalId: '1065432109',
      dateOfBirth: '2010-02-18',
      gender: 'FEMALE',
      bloodType: 'AB+',
      nationality: 'سعودية',
      admissionDate: '2024-09-01',
      status: 'ACTIVE',
      emergencyContactName: 'سلطان القحطاني (الأب)',
      emergencyContactPhone: '+966505544332',
      emergencyContactRelationship: 'FATHER',
      giftedProgram: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.studentRecords.set(stdRec4.id, stdRec4);

    // School B Student Record (Elite)
    const stdRecB: StudentRecord = {
      id: `std_rec_${studentB.id}`,
      organizationId: schoolBId,
      studentId: studentB.id,
      nationalId: '2098765432',
      dateOfBirth: '2010-06-10',
      gender: 'MALE',
      bloodType: 'O+',
      nationality: 'سعودي',
      admissionDate: '2024-09-01',
      status: 'ACTIVE',
      emergencyContactName: 'James Hayes (Father)',
      emergencyContactPhone: '+966551122334',
      emergencyContactRelationship: 'FATHER',
      giftedProgram: true,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    };
    this.studentRecords.set(stdRecB.id, stdRecB);

    // School A: Student Behavior & Merit Records
    const beh1: StudentBehaviorRecord = {
      id: `beh_horizon_001`,
      organizationId: schoolAId,
      studentId: student1.id,
      studentName: student1.fullName,
      type: 'MERIT',
      title: 'التفوق في أولمبياد الرياضيات المدرسي',
      description: 'حقق المركز الأول على مستوى المدرسة في مسابقة حل المسائل المتقدمة',
      points: 10,
      actionTaken: 'منح شهادة تفوق مع إشعار ولي الأمر',
      incidentDate: '2026-09-15',
      recordedBy: teacherMath.id,
      recordedByName: teacherMath.fullName,
      status: 'RESOLVED',
      createdAt: '2026-09-15T10:00:00Z',
    };
    this.studentBehaviorRecords.set(beh1.id, beh1);

    const beh2: StudentBehaviorRecord = {
      id: `beh_horizon_002`,
      organizationId: schoolAId,
      studentId: student2.id,
      studentName: student2.fullName,
      type: 'POSITIVE_PRAISE',
      title: 'مشاركة متميزة في الإذاعة المدرسية',
      description: 'إلقاء مميز وإعداد محتوى ثقافي هادف للإذاعة المدرسية الصباحية',
      points: 5,
      actionTaken: 'تسجيل بطاقة تميز سلوكي',
      incidentDate: '2026-09-20',
      recordedBy: teacherArabic.id,
      recordedByName: teacherArabic.fullName,
      status: 'RESOLVED',
      createdAt: '2026-09-20T08:30:00Z',
    };
    this.studentBehaviorRecords.set(beh2.id, beh2);

    const beh3: StudentBehaviorRecord = {
      id: `beh_horizon_003`,
      organizationId: schoolAId,
      studentId: student3.id,
      studentName: student3.fullName,
      type: 'MINOR_INFRACTION',
      title: 'تأخر متكرر عن الحصة الأولى',
      description: 'تأخر 3 مرات خلال الأسبوع دون إحضار عذر مسبق',
      points: -2,
      actionTaken: 'تنبيه شفهي والتواصل مع ولي الأمر',
      incidentDate: '2026-09-28',
      recordedBy: teacherMath.id,
      recordedByName: teacherMath.fullName,
      status: 'RESOLVED',
      createdAt: '2026-09-28T09:00:00Z',
    };
    this.studentBehaviorRecords.set(beh3.id, beh3);

    // School A: Student Lifecycle Events
    const lce1: StudentLifecycleEvent = {
      id: `lce_horizon_001`,
      organizationId: schoolAId,
      studentId: student1.id,
      studentName: student1.fullName,
      previousStatus: 'ACTIVE',
      newStatus: 'ACTIVE',
      reason: 'القبول والتسجيل الأكاديمي للعام الدراسي 2026-2027',
      actionBy: adminA.id,
      actionByName: adminA.fullName,
      effectiveDate: '2026-08-20',
      timestamp: '2026-08-20T08:00:00Z',
    };
    this.studentLifecycleEvents.set(lce1.id, lce1);

    // School A: Parent Student Links
    const psl1: ParentStudentLink = {
      id: `psl_horizon_001`,
      organizationId: schoolAId,
      parentId: parent1.id,
      parentName: parent1.fullName,
      studentId: student1.id,
      studentName: student1.fullName,
      relationship: 'FATHER',
      isEmergencyContact: true,
      createdAt: '2026-01-01T00:00:00Z',
    };
    this.parentStudentLinks.set(psl1.id, psl1);

    const psl2: ParentStudentLink = {
      id: `psl_horizon_002`,
      organizationId: schoolAId,
      parentId: parent1.id,
      parentName: parent1.fullName,
      studentId: student3.id,
      studentName: student3.fullName,
      relationship: 'FATHER',
      isEmergencyContact: true,
      createdAt: '2026-01-01T00:00:00Z',
    };
    this.parentStudentLinks.set(psl2.id, psl2);

    // School A: Attendance Sessions
    const sess1Id = 'att_sess_horizon_001';
    this.attendanceSessions.set(sess1Id, {
      id: sess1Id,
      organizationId: schoolAId,
      classroomId: class10AId,
      classroomName: 'شعبة 10-أ (علمي)',
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات - الصف العاشر (شعبة أ)',
      date: today,
      periodNumber: 1,
      title: 'جلسة تحضير الحصة الأولى - الجبر الخطي',
      status: 'COMPLETED',
      openedBy: teacherMath.id,
      openedByName: teacherMath.fullName,
      presentCount: 2,
      absentCount: 0,
      lateCount: 1,
      excusedCount: 0,
      totalStudents: 3,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Update existing attendance records with sessionId
    const attRec1 = this.attendanceRecords.get(`att_${courseMath10AId}_${student1.id}_${today}`);
    if (attRec1) {
      attRec1.sessionId = sess1Id;
      attRec1.classroomName = 'شعبة 10-أ (علمي)';
      attRec1.studentIdNumber = student1.studentIdNumber;
      attRec1.recordedByName = teacherMath.fullName;
    }
    const attRec2 = this.attendanceRecords.get(`att_${courseMath10AId}_${student2.id}_${today}`);
    if (attRec2) {
      attRec2.sessionId = sess1Id;
      attRec2.classroomName = 'شعبة 10-أ (علمي)';
      attRec2.studentIdNumber = student2.studentIdNumber;
      attRec2.recordedByName = teacherMath.fullName;
    }
    const attRec3 = this.attendanceRecords.get(`att_${courseMath10AId}_${student3.id}_${today}`);
    if (attRec3) {
      attRec3.sessionId = sess1Id;
      attRec3.classroomName = 'شعبة 10-أ (علمي)';
      attRec3.studentIdNumber = student3.studentIdNumber;
      attRec3.recordedByName = teacherMath.fullName;
    }

    // Additional historic attendance for student1 (to show rich summary)
    const histDates = ['2026-09-01', '2026-09-02', '2026-09-03', '2026-09-04', '2026-09-07'];
    for (let i = 0; i < histDates.length; i++) {
      const d = histDates[i];
      const recKey = `att_${courseMath10AId}_${student1.id}_${d}`;
      this.attendanceRecords.set(recKey, {
        id: recKey,
        organizationId: schoolAId,
        courseId: courseMath10AId,
        classroomId: class10AId,
        classroomName: 'شعبة 10-أ (علمي)',
        studentId: student1.id,
        studentName: student1.fullName,
        studentIdNumber: student1.studentIdNumber,
        recordedBy: teacherMath.id,
        recordedByName: teacherMath.fullName,
        date: d,
        status: i === 3 ? 'EXCUSED' : 'PRESENT',
        notes: i === 3 ? 'إجازة مرضية معتمدة' : undefined,
        createdAt: `${d}T08:00:00Z`,
      });
    }

    // School A: Assessments (Course-based evaluations)
    const assMathMidterm: Assessment = {
      id: 'ass_math_midterm_10a',
      organizationId: schoolAId,
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات - الصف العاشر (شعبة أ)',
      subjectId: mathSubId,
      subjectName: 'الرياضيات العامة والتحليل',
      classroomId: class10AId,
      classroomName: 'شعبة 10-أ (علمي)',
      termId: termAId,
      title: 'اختبار منتصف الفصل الأول في الرياضيات',
      description: 'يشمل وحدات الدوال والمصفوفات والمتجهات',
      category: 'MIDTERM',
      maxScore: 100,
      weightPercentage: 30,
      dueDate: '2026-10-15T12:00:00Z',
      assessmentDate: '2026-10-15',
      status: 'PUBLISHED',
      createdBy: teacherMath.id,
      createdByName: teacherMath.fullName,
      createdAt: '2026-09-01T08:00:00Z',
      updatedAt: '2026-09-01T08:00:00Z',
    };
    this.assessments.set(assMathMidterm.id, assMathMidterm);

    const assMathQuiz1: Assessment = {
      id: 'ass_math_quiz1_10a',
      organizationId: schoolAId,
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات - الصف العاشر (شعبة أ)',
      subjectId: mathSubId,
      subjectName: 'الرياضيات العامة والتحليل',
      classroomId: class10AId,
      classroomName: 'شعبة 10-أ (علمي)',
      termId: termAId,
      title: 'اختبار قصير (1): الدوال واللوغاريتمات',
      description: 'تقييم سريع على فهم التحويل اللوغاريتمي',
      category: 'QUIZ',
      maxScore: 20,
      weightPercentage: 10,
      dueDate: '2026-09-25T10:00:00Z',
      assessmentDate: '2026-09-25',
      status: 'PUBLISHED',
      createdBy: teacherMath.id,
      createdByName: teacherMath.fullName,
      createdAt: '2026-09-05T08:00:00Z',
      updatedAt: '2026-09-05T08:00:00Z',
    };
    this.assessments.set(assMathQuiz1.id, assMathQuiz1);

    const assMathProject: Assessment = {
      id: 'ass_math_project_10a',
      organizationId: schoolAId,
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات - الصف العاشر (شعبة أ)',
      subjectId: mathSubId,
      subjectName: 'الرياضيات العامة والتحليل',
      classroomId: class10AId,
      classroomName: 'شعبة 10-أ (علمي)',
      termId: termAId,
      title: 'مشروع الفصل: التطبيقات الواقعية للجبر',
      description: 'بحث جماعي عن استخدام الخوارزميات المصفوفية في الرسوم الحاسوبية',
      category: 'PROJECT',
      maxScore: 50,
      weightPercentage: 20,
      dueDate: '2026-11-10T23:59:00Z',
      assessmentDate: '2026-11-10',
      status: 'PUBLISHED',
      createdBy: teacherMath.id,
      createdByName: teacherMath.fullName,
      createdAt: '2026-09-10T08:00:00Z',
      updatedAt: '2026-09-10T08:00:00Z',
    };
    this.assessments.set(assMathProject.id, assMathProject);

    const assArabExam: Assessment = {
      id: 'ass_arab_exam_10a',
      organizationId: schoolAId,
      courseId: courseArabic10AId,
      courseTitle: 'اللغة العربية والبلاغة - الصف العاشر (شعبة أ)',
      subjectId: arabicSubId,
      subjectName: 'اللغة العربية والأدب',
      classroomId: class10AId,
      classroomName: 'شعبة 10-أ (علمي)',
      termId: termAId,
      title: 'اختبار النحو والبلاغة التحليلي',
      description: 'إعراب نصوص شعرية وتحليل الاستعارة والمجاز',
      category: 'EXAM',
      maxScore: 100,
      weightPercentage: 40,
      dueDate: '2026-10-20T11:00:00Z',
      assessmentDate: '2026-10-20',
      status: 'PUBLISHED',
      createdBy: teacherArabic.id,
      createdByName: teacherArabic.fullName,
      createdAt: '2026-09-02T08:00:00Z',
      updatedAt: '2026-09-02T08:00:00Z',
    };
    this.assessments.set(assArabExam.id, assArabExam);

    // School A: Assessment Grades
    // Student 1 (عمر خالد السعيد)
    const gr1_1: AssessmentGrade = {
      id: `grd_${assMathMidterm.id}_${student1.id}`,
      organizationId: schoolAId,
      assessmentId: assMathMidterm.id,
      assessmentTitle: assMathMidterm.title,
      assessmentCategory: assMathMidterm.category,
      maxScore: assMathMidterm.maxScore,
      studentId: student1.id,
      studentName: student1.fullName,
      studentIdNumber: student1.studentIdNumber,
      score: 96,
      percentage: 96,
      feedback: 'أداء ممتاز وتحليل رياضي دقيق جداً',
      gradedBy: teacherMath.id,
      gradedByName: teacherMath.fullName,
      gradedAt: '2026-10-16T10:00:00Z',
      updatedAt: '2026-10-16T10:00:00Z',
    };
    this.assessmentGrades.set(gr1_1.id, gr1_1);

    const gr1_2: AssessmentGrade = {
      id: `grd_${assMathQuiz1.id}_${student1.id}`,
      organizationId: schoolAId,
      assessmentId: assMathQuiz1.id,
      assessmentTitle: assMathQuiz1.title,
      assessmentCategory: assMathQuiz1.category,
      maxScore: assMathQuiz1.maxScore,
      studentId: student1.id,
      studentName: student1.fullName,
      studentIdNumber: student1.studentIdNumber,
      score: 19.5,
      percentage: 97.5,
      feedback: 'إجابة نموذجية وسريعة',
      gradedBy: teacherMath.id,
      gradedByName: teacherMath.fullName,
      gradedAt: '2026-09-26T11:00:00Z',
      updatedAt: '2026-09-26T11:00:00Z',
    };
    this.assessmentGrades.set(gr1_2.id, gr1_2);

    const gr1_3: AssessmentGrade = {
      id: `grd_${assArabExam.id}_${student1.id}`,
      organizationId: schoolAId,
      assessmentId: assArabExam.id,
      assessmentTitle: assArabExam.title,
      assessmentCategory: assArabExam.category,
      maxScore: assArabExam.maxScore,
      studentId: student1.id,
      studentName: student1.fullName,
      studentIdNumber: student1.studentIdNumber,
      score: 93,
      percentage: 93,
      feedback: 'أسلوب لغوي رصين وإعراب دقيق',
      gradedBy: teacherArabic.id,
      gradedByName: teacherArabic.fullName,
      gradedAt: '2026-10-21T09:00:00Z',
      updatedAt: '2026-10-21T09:00:00Z',
    };
    this.assessmentGrades.set(gr1_3.id, gr1_3);

    // Student 2 (نورة العتيبي)
    const gr2_1: AssessmentGrade = {
      id: `grd_${assMathMidterm.id}_${student2.id}`,
      organizationId: schoolAId,
      assessmentId: assMathMidterm.id,
      assessmentTitle: assMathMidterm.title,
      assessmentCategory: assMathMidterm.category,
      maxScore: assMathMidterm.maxScore,
      studentId: student2.id,
      studentName: student2.fullName,
      studentIdNumber: student2.studentIdNumber,
      score: 91,
      percentage: 91,
      feedback: 'مستوى رائع ومتقن',
      gradedBy: teacherMath.id,
      gradedByName: teacherMath.fullName,
      gradedAt: '2026-10-16T10:30:00Z',
      updatedAt: '2026-10-16T10:30:00Z',
    };
    this.assessmentGrades.set(gr2_1.id, gr2_1);

    const gr2_2: AssessmentGrade = {
      id: `grd_${assMathQuiz1.id}_${student2.id}`,
      organizationId: schoolAId,
      assessmentId: assMathQuiz1.id,
      assessmentTitle: assMathQuiz1.title,
      assessmentCategory: assMathQuiz1.category,
      maxScore: assMathQuiz1.maxScore,
      studentId: student2.id,
      studentName: student2.fullName,
      studentIdNumber: student2.studentIdNumber,
      score: 18,
      percentage: 90,
      feedback: 'أحسنتِ يا نورة',
      gradedBy: teacherMath.id,
      gradedByName: teacherMath.fullName,
      gradedAt: '2026-09-26T11:30:00Z',
      updatedAt: '2026-09-26T11:30:00Z',
    };
    this.assessmentGrades.set(gr2_2.id, gr2_2);

    // Student 3 (فيصل المطيري)
    const gr3_1: AssessmentGrade = {
      id: `grd_${assMathMidterm.id}_${student3.id}`,
      organizationId: schoolAId,
      assessmentId: assMathMidterm.id,
      assessmentTitle: assMathMidterm.title,
      assessmentCategory: assMathMidterm.category,
      maxScore: assMathMidterm.maxScore,
      studentId: student3.id,
      studentName: student3.fullName,
      studentIdNumber: student3.studentIdNumber,
      score: 82,
      percentage: 82,
      feedback: 'جهد طيب مع الحاجة لمزيد من التمرن على المصفوفات',
      gradedBy: teacherMath.id,
      gradedByName: teacherMath.fullName,
      gradedAt: '2026-10-16T11:00:00Z',
      updatedAt: '2026-10-16T11:00:00Z',
    };
    this.assessmentGrades.set(gr3_1.id, gr3_1);

    // School B: Assessments & Grades (Tenant Isolation Test Verification)
    const assPhysB: Assessment = {
      id: 'ass_elite_phys_midterm',
      organizationId: schoolBId,
      courseId: coursePhys10AId,
      courseTitle: 'Advanced Physics - Grade 10',
      subjectId: physSubId,
      subjectName: 'Advanced Physics',
      classroomId: classBId,
      classroomName: 'Section 10-Alpha',
      termId: termBId,
      title: 'Midterm Exam - Classical & Modern Physics',
      description: 'Kinematics, dynamics, and quantum fundamentals',
      category: 'MIDTERM',
      maxScore: 100,
      weightPercentage: 35,
      dueDate: '2026-10-25T14:00:00Z',
      assessmentDate: '2026-10-25',
      status: 'PUBLISHED',
      createdBy: teacherB.id,
      createdByName: teacherB.fullName,
      createdAt: '2026-09-05T08:00:00Z',
      updatedAt: '2026-09-05T08:00:00Z',
    };
    this.assessments.set(assPhysB.id, assPhysB);

    const grB_1: AssessmentGrade = {
      id: `grd_${assPhysB.id}_${studentB.id}`,
      organizationId: schoolBId,
      assessmentId: assPhysB.id,
      assessmentTitle: assPhysB.title,
      assessmentCategory: assPhysB.category,
      maxScore: assPhysB.maxScore,
      studentId: studentB.id,
      studentName: studentB.fullName,
      studentIdNumber: studentB.studentIdNumber,
      score: 95,
      percentage: 95,
      feedback: 'Outstanding analytical rigor',
      gradedBy: teacherB.id,
      gradedByName: teacherB.fullName,
      gradedAt: '2026-10-26T10:00:00Z',
      updatedAt: '2026-10-26T10:00:00Z',
    };
    this.assessmentGrades.set(grB_1.id, grB_1);

    const sessBId = 'att_sess_elite_001';
    this.attendanceSessions.set(sessBId, {
      id: sessBId,
      organizationId: schoolBId,
      classroomId: classBId,
      classroomName: 'Section 10-Alpha',
      courseId: coursePhys10AId,
      courseTitle: 'Advanced Physics - Grade 10',
      date: today,
      periodNumber: 2,
      title: 'Morning Lab Session Roll Call',
      status: 'COMPLETED',
      openedBy: teacherB.id,
      openedByName: teacherB.fullName,
      presentCount: 1,
      absentCount: 0,
      lateCount: 0,
      excusedCount: 0,
      totalStudents: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    const attRecB: AttendanceRecord = {
      id: `att_${coursePhys10AId}_${studentB.id}_${today}`,
      organizationId: schoolBId,
      sessionId: sessBId,
      courseId: coursePhys10AId,
      classroomId: classBId,
      classroomName: 'Section 10-Alpha',
      studentId: studentB.id,
      studentName: studentB.fullName,
      studentIdNumber: studentB.studentIdNumber,
      recordedBy: teacherB.id,
      recordedByName: teacherB.fullName,
      date: today,
      status: 'PRESENT',
      createdAt: new Date().toISOString(),
    };
    this.attendanceRecords.set(attRecB.id, attRecB);

    // Populate Organization Memberships & default auth providers for all seeded users
    for (const user of Array.from(this.users.values())) {
      user.emailVerified = true;
      user.phoneVerified = true;
      user.authProviders = ['email'];
      if (!user.passwordHash) {
        user.passwordHash = hashPassword('Password@2026');
      }
      this.addMembership({
        userId: user.id,
        organizationId: user.organizationId,
        role: user.role,
        isDefault: true,
        status: 'ACTIVE',
        classroomId: user.classroomId,
        studentIdNumber: user.studentIdNumber,
        teacherSpecialization: user.teacherSpecialization,
      });
    }

    // Seed realistic notifications
    this.createNotification({
      organizationId: schoolAId,
      recipientId: student1.id,
      recipientRole: 'STUDENT',
      type: 'ASSIGNMENT_CREATED',
      title: 'واجب جديد: الدوال الأسية واللوغاريتمات',
      body: 'قام أستاذ الرياضيات بإضافة واجب جديد في مقرر الرياضيات - شعبة 10-أ.',
      channels: ['IN_APP', 'EMAIL'],
      data: { courseId: courseMath10AId },
    });

    this.createNotification({
      organizationId: schoolAId,
      recipientId: parent1.id,
      recipientRole: 'PARENT',
      type: 'BEHAVIOR_LOGGED',
      title: 'إشادة تفوق وتميز أكاديمي',
      body: 'تم تسجيل بطاقة تفوق للطالب عمر خالد السعيد لحصوله على المركز الأول في أولمبياد الرياضيات.',
      channels: ['IN_APP', 'EMAIL', 'WHATSAPP'],
      data: { studentId: student1.id },
    });

    this.createNotification({
      organizationId: schoolAId,
      recipientId: teacherMath.id,
      recipientRole: 'TEACHER',
      type: 'ANNOUNCEMENT',
      title: 'تذكير: رصد درجات الاختبارات التكوينية',
      body: 'يرجى مراجعة سجلات الدرجات وإتمام اعتماد نتائج الاختبارات للفصل الدراسي الأول.',
      channels: ['IN_APP'],
    });

    this.createNotification({
      organizationId: schoolAId,
      recipientId: adminA.id,
      recipientRole: 'ORG_ADMIN',
      type: 'SYSTEM_ALERT',
      title: 'تقرير التحليلات الأكاديمية الأسبوعي جاهز',
      body: 'تم توليد تقرير مؤشرات الأداء والتدخل المبكر للمدرسة تلقائياً عبر الذكاء الاصطناعي.',
      channels: ['IN_APP'],
    });

    // School A: Curriculum Units (Structured Units)
    const unit1MathId = 'unit_horizon_math_01';
    this.curriculumUnits.set(unit1MathId, {
      id: unit1MathId,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات المتقدمة - الصف العاشر',
      title: 'الوحدة الأولى: الجبر والتحليل الرياضي المتقدم',
      description: 'الدوال الأسية واللوغاريتمية، حل المعادلات غير الخطية، وتطبيقات النمذجة الرياضية',
      orderIndex: 1,
      isPublished: true,
      createdAt: '2026-08-25T08:00:00Z',
      updatedAt: '2026-08-25T08:00:00Z',
    });

    const unit2MathId = 'unit_horizon_math_02';
    this.curriculumUnits.set(unit2MathId, {
      id: unit2MathId,
      organizationId: schoolAId,
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات المتقدمة - الصف العاشر',
      title: 'الوحدة الثانية: الجبر الخطي والمصفوفات والمحددات',
      description: 'العمليات على المصفوفات، إيجاد النظير الضربي، وتطبيقات حل أنظمة المعادلات الخطية',
      orderIndex: 2,
      isPublished: true,
      createdAt: '2026-08-25T08:00:00Z',
      updatedAt: '2026-08-25T08:00:00Z',
    });

    const unit1PhysId = 'unit_horizon_phys_01';
    this.curriculumUnits.set(unit1PhysId, {
      id: unit1PhysId,
      organizationId: schoolAId,
      courseId: coursePhys10AId,
      courseTitle: 'الفيزياء التجريبية والميكانيكا',
      title: 'الوحدة الأولى: علم الحركة والميكانيكا الكلاسيكية',
      description: 'قوانين نيوتن للحركة، كمية الحركة والاصطدامات، والطاقة والشغل الميكانيكي',
      orderIndex: 1,
      isPublished: true,
      createdAt: '2026-08-25T08:00:00Z',
      updatedAt: '2026-08-25T08:00:00Z',
    });

    // Update lessons with unit link
    const les1 = this.lessons.get(lesson1Id);
    if (les1) {
      les1.unitId = unit1MathId;
      les1.unitTitle = 'الوحدة الأولى: الجبر والتحليل الرياضي المتقدم';
    }
    const les2 = this.lessons.get(lesson2Id);
    if (les2) {
      les2.unitId = unit2MathId;
      les2.unitTitle = 'الوحدة الثانية: الجبر الخطي والمصفوفات والمحددات';
    }

    // School A: Digital Learning Library Resources (Multi-Format, Rich Educational Assets)
    const res1Id = 'res_horizon_math_doc1';
    this.libraryResources.set(res1Id, {
      id: res1Id,
      organizationId: schoolAId,
      title: 'الدليل الشامل في حل المعادلات اللوغاريتمية والأسية',
      description: 'مذكرة تدريبية مكثفة تحوي 50 مسألة محلولة بالتفصيل مع خرائط مفاهيمية للتحويل اللوغاريتمي.',
      resourceType: 'DOCUMENT',
      format: 'pdf',
      subjectId: mathSubId,
      subjectName: 'الرياضيات العامة والتحليل',
      gradeLevelId: grade10Id,
      gradeLevelName: 'الصف العاشر (الأول ثانوي)',
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات - الصف العاشر (شعبة أ)',
      unitId: unit1MathId,
      unitTitle: 'الوحدة الأولى: الجبر والتحليل الرياضي المتقدم',
      lessonId: lesson1Id,
      lessonTitle: 'مقدمة في الدوال الأسية واللوغاريتمات',
      externalUrl: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf',
      fileSize: 2450000,
      fileType: 'application/pdf',
      tags: ['رياضيات', 'لوغاريتمات', 'دوال أسية', 'أول ثانوي', 'حلول نموذجية'],
      uploadedBy: teacherMath.id,
      authorName: teacherMath.fullName,
      visibility: 'PUBLIC_SCHOOL',
      status: 'PUBLISHED',
      viewCount: 142,
      downloadCount: 88,
      completionCount: 65,
      aiSearchable: true,
      aiSummary: 'دليل تدريبي شامل يركز على قوانين اللوغاريتمات الطبيعية والمعتادة وخطوات تبسيط المعادلات الأسية.',
      createdAt: '2026-09-01T10:00:00Z',
      updatedAt: '2026-09-01T10:00:00Z',
    });

    const res2Id = 'res_horizon_math_video1';
    this.libraryResources.set(res2Id, {
      id: res2Id,
      organizationId: schoolAId,
      title: 'شرح مرئي: التطبيقات الحقيقية للمصفوفات في الذكاء الاصطناعي',
      description: 'فيديو تفاعلي عالي الدقة يشرح كيفية تحويل الصور إلى مصفوفات ثنائية وتطبيق فلاتر الالتفاف الجبري.',
      resourceType: 'VIDEO',
      format: 'youtube',
      subjectId: mathSubId,
      subjectName: 'الرياضيات العامة والتحليل',
      gradeLevelId: grade10Id,
      gradeLevelName: 'الصف العاشر (الأول ثانوي)',
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات - الصف العاشر (شعبة أ)',
      unitId: unit2MathId,
      unitTitle: 'الوحدة الثانية: الجبر الخطي والمصفوفات والمحددات',
      lessonId: lesson2Id,
      lessonTitle: 'المصفوفات والعمليات الجبرية الخطية',
      externalUrl: 'https://www.youtube.com/watch?v=fNk_zzaMoSs',
      fileSize: 0,
      fileType: 'video/youtube',
      tags: ['مصفوفات', 'ذكاء اصطناعي', 'شرح مرئي', 'جبر خطي'],
      uploadedBy: teacherMath.id,
      authorName: teacherMath.fullName,
      visibility: 'PUBLIC_SCHOOL',
      status: 'PUBLISHED',
      viewCount: 290,
      downloadCount: 45,
      completionCount: 180,
      aiSearchable: true,
      aiSummary: 'فيديو تعليمي يوضح العلاقة بين العمليات المصفوفية وتدريب الشبكات العصبية ومعالجة الصور الرقمية.',
      createdAt: '2026-09-08T11:00:00Z',
      updatedAt: '2026-09-08T11:00:00Z',
    });

    const res3Id = 'res_horizon_phys_sim1';
    this.libraryResources.set(res3Id, {
      id: res3Id,
      organizationId: schoolAId,
      title: 'مختبر افتراضي تفاعلي: محاكاة قوانين الحركة وقوى الاحتكاك',
      description: 'تطبيق محاكاة فيزيائي تفاعلي يسمح للطالب بتغيير زاوية السطح المائل ومعامل الاحتكاك وملاحظة التسارع بيانياً.',
      resourceType: 'INTERACTIVE',
      format: 'web_link',
      subjectId: physicsSubId,
      subjectName: 'الفيزياء التجريبية والميكانيكا',
      gradeLevelId: grade10Id,
      gradeLevelName: 'الصف العاشر (الأول ثانوي)',
      courseId: coursePhys10AId,
      courseTitle: 'الفيزياء - الصف العاشر (شعبة أ)',
      unitId: unit1PhysId,
      unitTitle: 'الوحدة الأولى: علم الحركة والميكانيكا الكلاسيكية',
      externalUrl: 'https://phet.colorado.edu/sims/html/forces-and-motion-basics/latest/forces-and-motion-basics_all.html',
      fileSize: 0,
      fileType: 'text/html',
      tags: ['فيزياء', 'مختبر افتراضي', 'قوانين نيوتن', 'محاكاة', 'تجارب تفاعلية'],
      uploadedBy: teacherMath.id,
      authorName: teacherMath.fullName,
      visibility: 'COURSE_STUDENTS',
      status: 'PUBLISHED',
      viewCount: 185,
      downloadCount: 0,
      completionCount: 110,
      aiSearchable: true,
      aiSummary: 'محاكاة تفاعلية لفهم محصلة القوى، التسارع، والتأثير المباشر للكتلة وقوة الاحتكاك على الأجسام.',
      createdAt: '2026-09-12T09:00:00Z',
      updatedAt: '2026-09-12T09:00:00Z',
    });

    const res4Id = 'res_horizon_arab_pres1';
    this.libraryResources.set(res4Id, {
      id: res4Id,
      organizationId: schoolAId,
      title: 'عرض تقديمي: فنون البلاغة العربية وعلم البيان',
      description: 'شرائح عرض تفاعلية مع شواهد قرآنية وأبيات شعرية معربة توضح الفروق بين الاستعارة التصريحية والمكنية.',
      resourceType: 'PRESENTATION',
      format: 'pptx',
      subjectId: arabicSubId,
      subjectName: 'اللغة العربية والأدب',
      gradeLevelId: grade10Id,
      gradeLevelName: 'الصف العاشر (الأول ثانوي)',
      courseId: courseArabic10AId,
      courseTitle: 'اللغة العربية والبلاغة - الصف العاشر (شعبة أ)',
      externalUrl: 'https://view.officeapps.live.com/op/view.aspx',
      fileSize: 5200000,
      fileType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      tags: ['لغة عربية', 'بلاغة', 'عرض تقديمي', 'استعارة', 'بيان'],
      uploadedBy: teacherArabic.id,
      authorName: teacherArabic.fullName,
      visibility: 'PUBLIC_SCHOOL',
      status: 'PUBLISHED',
      viewCount: 96,
      downloadCount: 42,
      completionCount: 50,
      aiSearchable: true,
      aiSummary: 'عرض تقديمي تعليمي شامل في علم البيان والبلاغة مع تمارين تطبيقية لتحليل الاستعارة والكناية.',
      createdAt: '2026-09-15T12:00:00Z',
      updatedAt: '2026-09-15T12:00:00Z',
    });

    const res5Id = 'res_horizon_math_sheet1';
    this.libraryResources.set(res5Id, {
      id: res5Id,
      organizationId: schoolAId,
      title: 'جدول حاسبي: حاسبة المصفوفات وحل المعادلات الآنية 3x3',
      description: 'جدول إكسيل احترافي مبرمج بالمعادلات الرياضية للتحقق الذاتي من حسابات محدد المصفوفة والمعكوس.',
      resourceType: 'SPREADSHEET',
      format: 'xlsx',
      subjectId: mathSubId,
      subjectName: 'الرياضيات العامة والتحليل',
      gradeLevelId: grade10Id,
      gradeLevelName: 'الصف العاشر (الأول ثانوي)',
      courseId: courseMath10AId,
      courseTitle: 'الرياضيات - الصف العاشر (شعبة أ)',
      unitId: unit2MathId,
      unitTitle: 'الوحدة الثانية: الجبر الخطي والمصفوفات والمحددات',
      externalUrl: 'https://view.officeapps.live.com/op/view.aspx',
      fileSize: 850000,
      fileType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      tags: ['جداول', 'إكسيل', 'حاسبة مصفوفات', 'تحقق ذاتي'],
      uploadedBy: teacherMath.id,
      authorName: teacherMath.fullName,
      visibility: 'TEACHERS_ONLY',
      status: 'PUBLISHED',
      viewCount: 38,
      downloadCount: 22,
      completionCount: 15,
      aiSearchable: true,
      aiSummary: 'نموذج جدول إلكتروني يساعد المعلمين على إعداد وتصحيح مسائل المصفوفات 3x3 بسرعة ودقة.',
      createdAt: '2026-09-18T14:00:00Z',
      updatedAt: '2026-09-18T14:00:00Z',
    });

    // Seed realistic learning activities
    this.resourceActivities.set('act_seed_01', {
      id: 'act_seed_01',
      organizationId: schoolAId,
      resourceId: res1Id,
      userId: student1.id,
      userName: student1.fullName,
      userRole: 'STUDENT',
      action: 'VIEWED',
      courseId: courseMath10AId,
      lessonId: lesson1Id,
      timestamp: '2026-09-05T14:20:00Z',
    });

    this.resourceActivities.set('act_seed_02', {
      id: 'act_seed_02',
      organizationId: schoolAId,
      resourceId: res1Id,
      userId: student1.id,
      userName: student1.fullName,
      userRole: 'STUDENT',
      action: 'DOWNLOADED',
      courseId: courseMath10AId,
      lessonId: lesson1Id,
      timestamp: '2026-09-05T14:25:00Z',
    });

    this.resourceActivities.set('act_seed_03', {
      id: 'act_seed_03',
      organizationId: schoolAId,
      resourceId: res2Id,
      userId: student2.id,
      userName: student2.fullName,
      userRole: 'STUDENT',
      action: 'COMPLETED',
      courseId: courseMath10AId,
      lessonId: lesson2Id,
      timestamp: '2026-09-10T16:00:00Z',
    });
  }

  // --- Multi-Tenant Query Helpers (Row-Level Security Enforcement) ---

  // Organizations
  getOrganizationById(orgId: string): Organization | undefined {
    return this.organizations.get(orgId);
  }

  getOrganizationBySlug(slug: string): Organization | undefined {
    return Array.from(this.organizations.values()).find((o) => o.slug === slug || o.id === slug);
  }

  getAllOrganizations(): Organization[] {
    return Array.from(this.organizations.values());
  }

  createOrganization(data: Omit<Organization, 'id' | 'createdAt' | 'updatedAt'>): Organization {
    const id = `org_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();
    const org: Organization = { ...data, id, createdAt: now, updatedAt: now };
    this.organizations.set(id, org);
    return org;
  }

  // Users (RLS Enforced by tenant organizationId)
  findUserByEmail(email: string, organizationId?: string): User | undefined {
    const normalized = email.trim().toLowerCase();
    const all = Array.from(this.users.values());
    if (organizationId) {
      return all.find((u) => u.email.toLowerCase() === normalized && u.organizationId === organizationId);
    }
    return all.find((u) => u.email.toLowerCase() === normalized);
  }

  findUserByPhone(phone: string, organizationId?: string): User | undefined {
    const normalized = phone.trim();
    const all = Array.from(this.users.values());
    if (organizationId) {
      return all.find((u) => u.phone && u.phone.trim() === normalized && u.organizationId === organizationId);
    }
    return all.find((u) => u.phone && u.phone.trim() === normalized);
  }

  findUserByGoogleId(googleId: string): User | undefined {
    const trimmed = googleId.trim();
    return Array.from(this.users.values()).find((u) => u.googleId === trimmed);
  }

  getUserById(userId: string, organizationId?: string): User | undefined {
    const user = this.users.get(userId);
    if (!user) return undefined;
    if (organizationId && user.organizationId !== organizationId) return undefined;
    return user;
  }

  getUsersByOrg(organizationId: string, role?: string): User[] {
    return Array.from(this.users.values()).filter((u) => {
      if (u.organizationId !== organizationId) return false;
      if (role && u.role !== role) return false;
      return true;
    });
  }

  createUser(data: Omit<User, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }): User {
    const id = data.id || `usr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();
    const user: User = {
      ...data,
      id,
      emailVerified: data.emailVerified ?? false,
      phoneVerified: data.phoneVerified ?? false,
      authProviders: data.authProviders || (data.email ? ['email'] : []),
      createdAt: now,
      updatedAt: now,
    };
    this.users.set(id, user);

    // Auto-create default OrganizationMembership if organizationId is present
    if (user.organizationId) {
      const existingMembership = this.getMembership(user.id, user.organizationId);
      if (!existingMembership) {
        this.addMembership({
          userId: user.id,
          organizationId: user.organizationId,
          role: user.role,
          isDefault: true,
          status: 'ACTIVE',
          classroomId: user.classroomId,
          studentIdNumber: user.studentIdNumber,
          teacherSpecialization: user.teacherSpecialization,
        });
      }
    }

    return user;
  }

  updateUser(id: string, organizationId?: string, updates: Partial<User> = {}): User | undefined {
    const user = organizationId ? this.getUserById(id, organizationId) : this.users.get(id);
    if (!user) return undefined;
    const updated: User = { ...user, ...updates, updatedAt: new Date().toISOString() };
    this.users.set(id, updated);
    return updated;
  }

  deleteUser(id: string, organizationId: string): boolean {
    const user = this.getUserById(id, organizationId);
    if (!user) return false;
    this.users.delete(id);
    // Delete memberships
    for (const [mId, mem] of this.organizationMemberships.entries()) {
      if (mem.userId === id) {
        this.organizationMemberships.delete(mId);
      }
    }
    return true;
  }

  // --- Account Linking & Identity Management ---
  linkAccountProvider(
    userId: string,
    provider: AuthProviderType,
    details?: { googleId?: string; phone?: string; email?: string }
  ): User | undefined {
    const user = this.users.get(userId);
    if (!user) return undefined;

    const currentProviders = new Set<AuthProviderType>(user.authProviders || []);
    currentProviders.add(provider);

    const updates: Partial<User> = {
      authProviders: Array.from(currentProviders),
    };

    if (provider === 'google' && details?.googleId) {
      updates.googleId = details.googleId;
    }
    if (provider === 'phone' && details?.phone) {
      updates.phone = details.phone;
      updates.phoneVerified = true;
    }
    if (provider === 'email' && details?.email) {
      updates.email = details.email.toLowerCase().trim();
      updates.emailVerified = true;
    }

    return this.updateUser(userId, undefined, updates);
  }

  unlinkAccountProvider(userId: string, provider: AuthProviderType): { success: boolean; user?: User; error?: string } {
    const user = this.users.get(userId);
    if (!user) return { success: false, error: 'USER_NOT_FOUND' };

    const currentProviders = user.authProviders || ['email'];
    if (currentProviders.length <= 1) {
      return { success: false, error: 'CANNOT_UNLINK_LAST_PROVIDER', user };
    }

    const updatedProviders = currentProviders.filter((p) => p !== provider);
    const updates: Partial<User> = {
      authProviders: updatedProviders,
    };

    if (provider === 'google') {
      updates.googleId = undefined;
    }

    const updatedUser = this.updateUser(userId, undefined, updates);
    return { success: true, user: updatedUser };
  }

  // --- Organization Memberships (Multi-Tenant User Roles) ---
  getMembershipsByUserId(userId: string): OrganizationMembership[] {
    return Array.from(this.organizationMemberships.values())
      .filter((m) => m.userId === userId && m.status !== 'REVOKED')
      .map((m) => {
        const org = this.getOrganizationById(m.organizationId);
        return {
          ...m,
          organizationName: org?.name,
          organizationSlug: org?.slug,
        };
      });
  }

  getMembershipById(id: string): OrganizationMembership | undefined {
    const mem = this.organizationMemberships.get(id);
    if (!mem || mem.status === 'REVOKED') return undefined;
    const org = this.getOrganizationById(mem.organizationId);
    return {
      ...mem,
      organizationName: org?.name,
      organizationSlug: org?.slug,
    };
  }

  getMembership(userId: string, organizationId: string): OrganizationMembership | undefined {
    return Array.from(this.organizationMemberships.values()).find(
      (m) => m.userId === userId && m.organizationId === organizationId && m.status !== 'REVOKED'
    );
  }

  addMembership(data: Omit<OrganizationMembership, 'id' | 'joinedAt'>): OrganizationMembership {
    const id = `mem_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const membership: OrganizationMembership = {
      ...data,
      id,
      joinedAt: new Date().toISOString(),
    };
    this.organizationMemberships.set(id, membership);
    return membership;
  }

  createMembership(data: Omit<OrganizationMembership, 'id' | 'joinedAt'>): OrganizationMembership {
    return this.addMembership(data);
  }

  updateMembership(id: string, updates: Partial<OrganizationMembership>): OrganizationMembership | undefined {
    const mem = this.organizationMemberships.get(id);
    if (!mem) return undefined;
    const updated = { ...mem, ...updates };
    this.organizationMemberships.set(id, updated);
    return updated;
  }

  removeMembership(id: string): boolean {
    return this.organizationMemberships.delete(id);
  }

  // --- Student Profiles (School-owned SIS records claimed by Users) ---
  getStudentProfileById(id: string, organizationId?: string): StudentProfile | undefined {
    const profile = this.studentProfiles.get(id);
    if (!profile) return undefined;
    if (organizationId && profile.organizationId !== organizationId) return undefined;
    return profile;
  }

  getStudentProfiles(
    organizationId: string,
    filters?: { classroomId?: string; gradeLevelId?: string; isClaimed?: boolean; search?: string }
  ): StudentProfile[] {
    return Array.from(this.studentProfiles.values()).filter((p) => {
      if (p.organizationId !== organizationId) return false;
      if (filters?.classroomId && p.classroomId !== filters.classroomId) return false;
      if (filters?.gradeLevelId && p.gradeLevelId !== filters.gradeLevelId) return false;
      if (filters?.isClaimed !== undefined && p.isClaimed !== filters.isClaimed) return false;
      if (filters?.search) {
        const q = filters.search.toLowerCase().trim();
        const matchName = p.fullName.toLowerCase().includes(q);
        const matchNumber = p.studentIdNumber?.toLowerCase().includes(q);
        if (!matchName && !matchNumber) return false;
      }
      return true;
    });
  }

  getStudentProfileByClaimToken(tokenHash: string): StudentProfile | undefined {
    const now = new Date().toISOString();
    return Array.from(this.studentProfiles.values()).find(
      (p) =>
        p.claimTokenHash === tokenHash &&
        !p.isClaimed &&
        (!p.claimTokenExpiresAt || p.claimTokenExpiresAt > now)
    );
  }

  createStudentProfile(data: Omit<StudentProfile, 'id' | 'createdAt' | 'updatedAt' | 'isClaimed'>): StudentProfile {
    const id = `stp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();
    const profile: StudentProfile = {
      ...data,
      id,
      isClaimed: false,
      createdAt: now,
      updatedAt: now,
    };
    this.studentProfiles.set(id, profile);
    return profile;
  }

  updateStudentProfile(id: string, organizationId: string, updates: Partial<StudentProfile>): StudentProfile | undefined {
    const profile = this.getStudentProfileById(id, organizationId);
    if (!profile) return undefined;
    const updated: StudentProfile = {
      ...profile,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.studentProfiles.set(id, updated);
    return updated;
  }

  claimStudentProfile(studentProfileId: string, organizationId: string, userId: string): StudentProfile | undefined {
    const profile = this.getStudentProfileById(studentProfileId, organizationId);
    if (!profile || profile.isClaimed) return undefined;

    const now = new Date().toISOString();
    const updated: StudentProfile = {
      ...profile,
      isClaimed: true,
      claimedByUserId: userId,
      claimedAt: now,
      claimTokenHash: undefined,
      claimTokenExpiresAt: undefined,
      updatedAt: now,
    };
    this.studentProfiles.set(studentProfileId, updated);
    return updated;
  }

  // --- Parent Link Tokens (Secure, Temporary, School-Scoped) ---
  createParentLinkToken(
    data: Omit<ParentLinkToken, 'id' | 'isUsed' | 'createdAt'>
  ): ParentLinkToken {
    const id = `plt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const token: ParentLinkToken = {
      ...data,
      id,
      isUsed: false,
      createdAt: new Date().toISOString(),
    };
    this.parentLinkTokens.set(id, token);
    return token;
  }

  getParentLinkTokenByHash(tokenHash: string): ParentLinkToken | undefined {
    const now = new Date().toISOString();
    return Array.from(this.parentLinkTokens.values()).find(
      (t) => t.tokenHash === tokenHash && !t.isUsed && t.expiresAt > now
    );
  }

  markParentLinkTokenUsed(id: string, usedByUserId: string): ParentLinkToken | undefined {
    const token = this.parentLinkTokens.get(id);
    if (!token) return undefined;
    const updated: ParentLinkToken = {
      ...token,
      isUsed: true,
      usedByUserId,
      usedAt: new Date().toISOString(),
    };
    this.parentLinkTokens.set(id, updated);
    return updated;
  }

  // --- Password Reset Tokens ---
  createPasswordResetToken(userId: string, email: string, tokenHash: string, expiresInMinutes = 60): PasswordResetToken {
    this.invalidatePasswordResetTokensForUser(userId);
    const id = `prt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString();
    const token: PasswordResetToken = {
      id,
      userId,
      email: email.toLowerCase().trim(),
      tokenHash,
      expiresAt,
      isUsed: false,
      createdAt: new Date().toISOString(),
    };
    this.passwordResetTokens.set(id, token);
    return token;
  }

  getPasswordResetTokenByHash(tokenHash: string): PasswordResetToken | undefined {
    return Array.from(this.passwordResetTokens.values()).find(
      (t) => t.tokenHash === tokenHash && !t.isUsed && new Date(t.expiresAt).getTime() > Date.now()
    );
  }

  markPasswordResetTokenUsed(id: string): void {
    const token = this.passwordResetTokens.get(id);
    if (token) {
      token.isUsed = true;
      token.usedAt = new Date().toISOString();
      this.passwordResetTokens.set(id, token);
    }
  }

  invalidatePasswordResetTokensForUser(userId: string): void {
    for (const [id, token] of this.passwordResetTokens.entries()) {
      if (token.userId === userId && !token.isUsed) {
        token.isUsed = true;
        this.passwordResetTokens.set(id, token);
      }
    }
  }

  // --- Email Verification Tokens ---
  createEmailVerificationToken(userId: string, email: string, tokenHash: string, expiresInMinutes = 24 * 60): EmailVerificationToken {
    const id = `evt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString();
    const token: EmailVerificationToken = {
      id,
      userId,
      email: email.toLowerCase().trim(),
      tokenHash,
      expiresAt,
      isUsed: false,
      createdAt: new Date().toISOString(),
    };
    this.emailVerificationTokens.set(id, token);
    return token;
  }

  getEmailVerificationTokenByHash(tokenHash: string): EmailVerificationToken | undefined {
    return Array.from(this.emailVerificationTokens.values()).find(
      (t) => t.tokenHash === tokenHash && !t.isUsed && new Date(t.expiresAt).getTime() > Date.now()
    );
  }

  markEmailVerificationTokenUsed(id: string): void {
    const token = this.emailVerificationTokens.get(id);
    if (token) {
      token.isUsed = true;
      token.usedAt = new Date().toISOString();
      this.emailVerificationTokens.set(id, token);
    }
  }

  // --- Phone Verification OTPs ---
  createPhoneOtp(phone: string, otpHash: string, userId?: string, expiresInMinutes = 10): PhoneVerificationOtp {
    const id = `otp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString();
    const record: PhoneVerificationOtp = {
      id,
      userId,
      phone: phone.trim(),
      otpHash,
      attemptsCount: 0,
      maxAttempts: 5,
      expiresAt,
      isUsed: false,
      createdAt: new Date().toISOString(),
    };
    this.phoneVerificationOtps.set(id, record);
    return record;
  }

  getLatestActivePhoneOtp(phone: string): PhoneVerificationOtp | undefined {
    const normalized = phone.trim();
    const matches = Array.from(this.phoneVerificationOtps.values())
      .filter((o) => o.phone === normalized && !o.isUsed && new Date(o.expiresAt).getTime() > Date.now())
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return matches[0];
  }

  incrementPhoneOtpAttempts(id: string): number {
    const record = this.phoneVerificationOtps.get(id);
    if (!record) return 0;
    record.attemptsCount += 1;
    if (record.attemptsCount >= record.maxAttempts) {
      record.isUsed = true; // Invalidate after exceeding max attempts to protect against brute force
    }
    this.phoneVerificationOtps.set(id, record);
    return record.attemptsCount;
  }

  markPhoneOtpUsed(id: string): void {
    const record = this.phoneVerificationOtps.get(id);
    if (record) {
      record.isUsed = true;
      record.usedAt = new Date().toISOString();
      this.phoneVerificationOtps.set(id, record);
    }
  }

  // Academic Structure
  private toDateString(value: unknown): string {
    return value instanceof Date ? value.toISOString().split('T')[0] : String(value);
  }

  private mapAcademicYearRow(row: any): AcademicYear {
    return {
      id: row.id,
      organizationId: row.organization_id,
      name: row.name,
      startDate: this.toDateString(row.start_date),
      endDate: this.toDateString(row.end_date),
      isCurrent: Boolean(row.is_current),
    };
  }

  private mapTermRow(row: any): Term {
    return {
      id: row.id,
      organizationId: row.organization_id,
      academicYearId: row.academic_year_id,
      name: row.name,
      startDate: this.toDateString(row.start_date),
      endDate: this.toDateString(row.end_date),
      isCurrent: Boolean(row.is_current),
    };
  }

  private mapGradeLevelRow(row: any): GradeLevel {
    return { id: row.id, organizationId: row.organization_id, name: row.name, sequenceOrder: Number(row.sequence_order) };
  }

  private mapClassroomRow(row: any): Classroom {
    return {
      id: row.id,
      organizationId: row.organization_id,
      gradeLevelId: row.grade_level_id,
      name: row.name,
      capacity: row.capacity === null ? undefined : Number(row.capacity),
    };
  }

  private mapSubjectRow(row: any): Subject {
    return {
      id: row.id,
      organizationId: row.organization_id,
      name: row.name,
      code: row.code,
      color: row.color || undefined,
      description: row.description || undefined,
    };
  }

  private mapCourseRow(row: any): Course {
    return {
      id: row.id,
      organizationId: row.organization_id,
      subjectId: row.subject_id,
      termId: row.term_id,
      teacherId: row.teacher_id || undefined,
      classroomId: row.classroom_id,
      title: row.title,
      description: row.description || undefined,
      subjectName: row.subject_name || undefined,
      teacherName: row.teacher_name || undefined,
      classroomName: row.classroom_name || undefined,
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
    };
  }

  private mapEnrollmentRow(row: any): StudentEnrollment {
    return {
      id: row.id,
      organizationId: row.organization_id,
      studentId: row.student_id,
      studentName: row.student_name || undefined,
      studentEmail: row.student_email || undefined,
      studentIdNumber: row.student_id_number || undefined,
      classroomId: row.classroom_id,
      classroomName: row.classroom_name || undefined,
      gradeLevelId: row.grade_level_id || undefined,
      gradeLevelName: row.grade_level_name || undefined,
      academicYearId: row.academic_year_id,
      academicYearName: row.academic_year_name || undefined,
      rollNumber: row.roll_number || undefined,
      status: row.status,
      enrolledAt: row.enrolled_at?.toISOString ? row.enrolled_at.toISOString() : String(row.enrolled_at),
      updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  private mapLessonRow(row: any): Lesson {
    return {
      id: row.id,
      organizationId: row.organization_id,
      courseId: row.course_id,
      unitId: row.unit_id || undefined,
      unitTitle: row.unit_title || undefined,
      title: row.title,
      contentHtml: row.content_html,
      mediaUrl: row.media_url || undefined,
      attachments: row.attachments || [],
      resourceIds: row.resource_ids || [],
      orderIndex: Number(row.order_index),
      isPublished: Boolean(row.is_published),
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
      updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  private mapAssignmentRow(row: any): Assignment {
    return {
      id: row.id,
      organizationId: row.organization_id,
      courseId: row.course_id,
      title: row.title,
      description: row.description,
      maxScore: Number(row.max_score),
      dueDate: row.due_date?.toISOString ? row.due_date.toISOString() : String(row.due_date),
      attachments: row.attachments || [],
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
    };
  }

  private mapTeacherAssignmentRow(row: any): TeacherAssignment {
    return {
      id: row.id,
      organizationId: row.organization_id,
      teacherId: row.teacher_id,
      teacherName: row.teacher_name || undefined,
      teacherEmail: row.teacher_email || undefined,
      courseId: row.course_id || undefined,
      courseTitle: row.course_title || undefined,
      subjectId: row.subject_id,
      subjectName: row.subject_name || undefined,
      classroomId: row.classroom_id,
      classroomName: row.classroom_name || undefined,
      academicYearId: row.academic_year_id || undefined,
      academicYearName: row.academic_year_name || undefined,
      role: row.role,
      weeklyHours: Number(row.weekly_hours),
      status: row.status,
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
      updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  async getLessonsByCourseAsync(courseId: string, organizationId: string): Promise<Lesson[]> {
    if (process.env.NODE_ENV !== 'production') return this.getLessonsByCourse(courseId, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `SELECT l.id, l.organization_id, l.course_id, l.unit_id, cu.title AS unit_title,
                l.title, l.content_html, l.media_url, l.attachments, l.resource_ids,
                l.order_index, l.is_published, l.created_at, l.updated_at
         FROM lessons l
         LEFT JOIN curriculum_units cu ON cu.id = l.unit_id AND cu.organization_id = l.organization_id
         WHERE l.organization_id = $1 AND l.course_id = $2
         ORDER BY l.order_index, l.id`,
        [organizationId, courseId]
      );
      return result.rows.map((row: any) => this.mapLessonRow(row));
    });
  }

  async getAssignmentsByCourseAsync(courseId: string, organizationId: string): Promise<Assignment[]> {
    if (process.env.NODE_ENV !== 'production') return this.getAssignmentsByCourse(courseId, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `SELECT id, organization_id, course_id, title, description, max_score,
                due_date, attachments, created_at
         FROM assignments
         WHERE organization_id = $1 AND course_id = $2
         ORDER BY due_date, id`,
        [organizationId, courseId]
      );
      return result.rows.map((row: any) => this.mapAssignmentRow(row));
    });
  }

  async getCourseStudentsAsync(courseId: string, classroomId: string, organizationId: string): Promise<User[]> {
    if (process.env.NODE_ENV !== 'production') {
      return this.getStudentsByClassroom(classroomId, organizationId);
    }
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `SELECT u.id, u.organization_id, u.email, u.password_hash, u.full_name, u.role,
                u.avatar_url, u.phone, u.student_id_number, u.teacher_specialization,
                u.classroom_id, u.email_verified, u.phone_verified, u.auth_providers,
                u.google_id, u.is_active, u.created_at, u.updated_at
         FROM student_enrollments e
         JOIN users u ON u.id = e.student_id AND u.organization_id = e.organization_id
         WHERE e.organization_id = $1 AND e.classroom_id = $2 AND e.status = 'ACTIVE'
               AND EXISTS (SELECT 1 FROM courses c
                           WHERE c.id = $3 AND c.organization_id = $1
                             AND c.classroom_id = e.classroom_id)
         ORDER BY u.full_name, u.id`,
        [organizationId, classroomId, courseId]
      );
      return result.rows.map((row: any) => this.mapUserRow(row));
    });
  }

  async getTeacherAssignmentsByCourseAsync(courseId: string, organizationId: string): Promise<TeacherAssignment[]> {
    if (process.env.NODE_ENV !== 'production') {
      return this.getTeacherAssignments(organizationId, { courseId });
    }
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `SELECT ta.id, ta.organization_id, ta.teacher_id, u.full_name AS teacher_name,
                u.email AS teacher_email, ta.course_id, c.title AS course_title,
                ta.subject_id, s.name AS subject_name, ta.classroom_id,
                cl.name AS classroom_name, ta.academic_year_id,
                ay.name AS academic_year_name, ta.role, ta.weekly_hours, ta.status,
                ta.created_at, ta.updated_at
         FROM teacher_assignments ta
         JOIN users u ON u.id = ta.teacher_id AND u.organization_id = ta.organization_id
         JOIN subjects s ON s.id = ta.subject_id AND s.organization_id = ta.organization_id
         JOIN classrooms cl ON cl.id = ta.classroom_id AND cl.organization_id = ta.organization_id
         LEFT JOIN courses c ON c.id = ta.course_id AND c.organization_id = ta.organization_id
         LEFT JOIN academic_years ay ON ay.id = ta.academic_year_id AND ay.organization_id = ta.organization_id
         WHERE ta.organization_id = $1 AND ta.course_id = $2 AND ta.status = 'ACTIVE'
         ORDER BY CASE WHEN ta.role = 'PRIMARY_TEACHER' THEN 0 ELSE 1 END, u.full_name, ta.id`,
        [organizationId, courseId]
      );
      return result.rows.map((row: any) => this.mapTeacherAssignmentRow(row));
    });
  }

  async getAcademicYearsAsync(organizationId: string): Promise<AcademicYear[]> {
    if (process.env.NODE_ENV !== 'production') return this.getAcademicYears(organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query('SELECT id, organization_id, name, start_date, end_date, is_current FROM academic_years WHERE organization_id = $1 ORDER BY start_date, id', [organizationId]);
      return result.rows.map((row: any) => this.mapAcademicYearRow(row));
    });
  }

  async getAcademicYearByIdAsync(id: string, organizationId: string): Promise<AcademicYear | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getAcademicYearById(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query('SELECT id, organization_id, name, start_date, end_date, is_current FROM academic_years WHERE id = $1 AND organization_id = $2', [id, organizationId]);
      return result.rows[0] ? this.mapAcademicYearRow(result.rows[0]) : undefined;
    });
  }

  async createAcademicYearAsync(data: Omit<AcademicYear, 'id'>): Promise<AcademicYear> {
    if (process.env.NODE_ENV !== 'production') return this.createAcademicYear(data);
    const id = generateId('year');
    return this.withIdentityTenant(data.organizationId, async (client) => {
      if (data.isCurrent) await client.query('UPDATE academic_years SET is_current = FALSE WHERE organization_id = $1', [data.organizationId]);
      const result = await client.query('INSERT INTO academic_years (id, organization_id, name, start_date, end_date, is_current) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, organization_id, name, start_date, end_date, is_current', [id, data.organizationId, data.name, data.startDate, data.endDate, data.isCurrent]);
      return this.mapAcademicYearRow(result.rows[0]);
    });
  }

  async updateAcademicYearAsync(id: string, organizationId: string, updates: Partial<AcademicYear>): Promise<AcademicYear | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateAcademicYear(id, organizationId, updates);
    return this.withIdentityTenant(organizationId, async (client) => {
      if (updates.isCurrent) await client.query('UPDATE academic_years SET is_current = FALSE WHERE organization_id = $1 AND id <> $2', [organizationId, id]);
      const result = await client.query('UPDATE academic_years SET name = COALESCE($3, name), start_date = COALESCE($4, start_date), end_date = COALESCE($5, end_date), is_current = COALESCE($6, is_current) WHERE id = $1 AND organization_id = $2 RETURNING id, organization_id, name, start_date, end_date, is_current', [id, organizationId, updates.name ?? null, updates.startDate ?? null, updates.endDate ?? null, updates.isCurrent ?? null]);
      return result.rows[0] ? this.mapAcademicYearRow(result.rows[0]) : undefined;
    });
  }

  async deleteAcademicYearAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteAcademicYear(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('DELETE FROM academic_years WHERE id = $1 AND organization_id = $2', [id, organizationId])).rowCount === 1);
  }

  async getTermsAsync(organizationId: string, academicYearId?: string): Promise<Term[]> {
    if (process.env.NODE_ENV !== 'production') return this.getTerms(organizationId, academicYearId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query('SELECT id, organization_id, academic_year_id, name, start_date, end_date, is_current FROM terms WHERE organization_id = $1 AND ($2::text IS NULL OR academic_year_id = $2) ORDER BY start_date, id', [organizationId, academicYearId || null]);
      return result.rows.map((row: any) => this.mapTermRow(row));
    });
  }

  async getTermByIdAsync(id: string, organizationId: string): Promise<Term | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getTermById(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query('SELECT id, organization_id, academic_year_id, name, start_date, end_date, is_current FROM terms WHERE id = $1 AND organization_id = $2', [id, organizationId]);
      return result.rows[0] ? this.mapTermRow(result.rows[0]) : undefined;
    });
  }

  async createTermAsync(data: Omit<Term, 'id'>): Promise<Term> {
    if (process.env.NODE_ENV !== 'production') return this.createTerm(data);
    const id = generateId('term');
    return this.withIdentityTenant(data.organizationId, async (client) => {
      if (data.isCurrent) await client.query('UPDATE terms SET is_current = FALSE WHERE organization_id = $1', [data.organizationId]);
      const result = await client.query('INSERT INTO terms (id, organization_id, academic_year_id, name, start_date, end_date, is_current) SELECT $1, $2, $3, $4, $5, $6, $7 WHERE EXISTS (SELECT 1 FROM academic_years WHERE id = $3 AND organization_id = $2) RETURNING id, organization_id, academic_year_id, name, start_date, end_date, is_current', [id, data.organizationId, data.academicYearId, data.name, data.startDate, data.endDate, data.isCurrent]);
      if (!result.rows[0]) throw new Error('INVALID_ACADEMIC_YEAR');
      return this.mapTermRow(result.rows[0]);
    });
  }

  async updateTermAsync(id: string, organizationId: string, updates: Partial<Term>): Promise<Term | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateTerm(id, organizationId, updates);
    return this.withIdentityTenant(organizationId, async (client) => {
      if (updates.isCurrent) await client.query('UPDATE terms SET is_current = FALSE WHERE organization_id = $1 AND id <> $2', [organizationId, id]);
      const result = await client.query('UPDATE terms SET academic_year_id = COALESCE($3, academic_year_id), name = COALESCE($4, name), start_date = COALESCE($5, start_date), end_date = COALESCE($6, end_date), is_current = COALESCE($7, is_current) WHERE id = $1 AND organization_id = $2 AND ($3::text IS NULL OR EXISTS (SELECT 1 FROM academic_years WHERE id = $3 AND organization_id = $2)) RETURNING id, organization_id, academic_year_id, name, start_date, end_date, is_current', [id, organizationId, updates.academicYearId ?? null, updates.name ?? null, updates.startDate ?? null, updates.endDate ?? null, updates.isCurrent ?? null]);
      return result.rows[0] ? this.mapTermRow(result.rows[0]) : undefined;
    });
  }

  async deleteTermAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteTerm(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('DELETE FROM terms WHERE id = $1 AND organization_id = $2', [id, organizationId])).rowCount === 1);
  }

  async getGradeLevelsAsync(organizationId: string): Promise<GradeLevel[]> {
    if (process.env.NODE_ENV !== 'production') return this.getGradeLevels(organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('SELECT id, organization_id, name, sequence_order FROM grade_levels WHERE organization_id = $1 ORDER BY sequence_order, id', [organizationId])).rows.map((row: any) => this.mapGradeLevelRow(row)));
  }

  async getGradeLevelByIdAsync(id: string, organizationId: string): Promise<GradeLevel | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getGradeLevelById(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query('SELECT id, organization_id, name, sequence_order FROM grade_levels WHERE id = $1 AND organization_id = $2', [id, organizationId]); return result.rows[0] ? this.mapGradeLevelRow(result.rows[0]) : undefined; });
  }

  async createGradeLevelAsync(data: Omit<GradeLevel, 'id'>): Promise<GradeLevel> {
    if (process.env.NODE_ENV !== 'production') return this.createGradeLevel(data);
    const id = generateId('grade');
    return this.withIdentityTenant(data.organizationId, async (client) => this.mapGradeLevelRow((await client.query('INSERT INTO grade_levels (id, organization_id, name, sequence_order) VALUES ($1, $2, $3, $4) RETURNING id, organization_id, name, sequence_order', [id, data.organizationId, data.name, data.sequenceOrder])).rows[0]));
  }

  async updateGradeLevelAsync(id: string, organizationId: string, updates: Partial<GradeLevel>): Promise<GradeLevel | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateGradeLevel(id, organizationId, updates);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query('UPDATE grade_levels SET name = COALESCE($3, name), sequence_order = COALESCE($4, sequence_order) WHERE id = $1 AND organization_id = $2 RETURNING id, organization_id, name, sequence_order', [id, organizationId, updates.name ?? null, updates.sequenceOrder ?? null]); return result.rows[0] ? this.mapGradeLevelRow(result.rows[0]) : undefined; });
  }

  async deleteGradeLevelAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteGradeLevel(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('DELETE FROM grade_levels WHERE id = $1 AND organization_id = $2', [id, organizationId])).rowCount === 1);
  }

  async getClassroomsAsync(organizationId: string, gradeLevelId?: string): Promise<Classroom[]> {
    if (process.env.NODE_ENV !== 'production') return this.getClassrooms(organizationId, gradeLevelId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('SELECT id, organization_id, grade_level_id, name, capacity FROM classrooms WHERE organization_id = $1 AND ($2::text IS NULL OR grade_level_id = $2) ORDER BY name, id', [organizationId, gradeLevelId || null])).rows.map((row: any) => this.mapClassroomRow(row)));
  }

  async getClassroomByIdAsync(id: string, organizationId: string): Promise<Classroom | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getClassroomById(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query('SELECT id, organization_id, grade_level_id, name, capacity FROM classrooms WHERE id = $1 AND organization_id = $2', [id, organizationId]); return result.rows[0] ? this.mapClassroomRow(result.rows[0]) : undefined; });
  }

  async createClassroomAsync(data: Omit<Classroom, 'id'>): Promise<Classroom> {
    if (process.env.NODE_ENV !== 'production') return this.createClassroom(data);
    const id = generateId('class');
    return this.withIdentityTenant(data.organizationId, async (client) => {
      const result = await client.query('INSERT INTO classrooms (id, organization_id, grade_level_id, name, capacity) SELECT $1, $2, $3, $4, $5 WHERE EXISTS (SELECT 1 FROM grade_levels WHERE id = $3 AND organization_id = $2) RETURNING id, organization_id, grade_level_id, name, capacity', [id, data.organizationId, data.gradeLevelId, data.name, data.capacity ?? 30]);
      if (!result.rows[0]) throw new Error('INVALID_GRADE_LEVEL');
      return this.mapClassroomRow(result.rows[0]);
    });
  }

  async updateClassroomAsync(id: string, organizationId: string, updates: Partial<Classroom>): Promise<Classroom | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateClassroom(id, organizationId, updates);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query('UPDATE classrooms SET grade_level_id = COALESCE($3, grade_level_id), name = COALESCE($4, name), capacity = COALESCE($5, capacity) WHERE id = $1 AND organization_id = $2 AND ($3::text IS NULL OR EXISTS (SELECT 1 FROM grade_levels WHERE id = $3 AND organization_id = $2)) RETURNING id, organization_id, grade_level_id, name, capacity', [id, organizationId, updates.gradeLevelId ?? null, updates.name ?? null, updates.capacity ?? null]); return result.rows[0] ? this.mapClassroomRow(result.rows[0]) : undefined; });
  }

  async deleteClassroomAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteClassroom(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('DELETE FROM classrooms WHERE id = $1 AND organization_id = $2', [id, organizationId])).rowCount === 1);
  }

  async getSubjectsAsync(organizationId: string): Promise<Subject[]> {
    if (process.env.NODE_ENV !== 'production') return this.getSubjects(organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('SELECT id, organization_id, name, code, color, description FROM subjects WHERE organization_id = $1 ORDER BY name, id', [organizationId])).rows.map((row: any) => this.mapSubjectRow(row)));
  }

  async getSubjectByIdAsync(id: string, organizationId: string): Promise<Subject | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getSubjectById(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query('SELECT id, organization_id, name, code, color, description FROM subjects WHERE id = $1 AND organization_id = $2', [id, organizationId]); return result.rows[0] ? this.mapSubjectRow(result.rows[0]) : undefined; });
  }

  async createSubjectAsync(data: Omit<Subject, 'id'>): Promise<Subject> {
    if (process.env.NODE_ENV !== 'production') return this.createSubject(data);
    const id = generateId('sub');
    return this.withIdentityTenant(data.organizationId, async (client) => this.mapSubjectRow((await client.query('INSERT INTO subjects (id, organization_id, name, code, color, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, organization_id, name, code, color, description', [id, data.organizationId, data.name, data.code, data.color ?? '#10b981', data.description ?? null])).rows[0]));
  }

  async updateSubjectAsync(id: string, organizationId: string, updates: Partial<Subject>): Promise<Subject | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateSubject(id, organizationId, updates);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query('UPDATE subjects SET name = COALESCE($3, name), code = COALESCE($4, code), color = COALESCE($5, color), description = COALESCE($6, description) WHERE id = $1 AND organization_id = $2 RETURNING id, organization_id, name, code, color, description', [id, organizationId, updates.name ?? null, updates.code ?? null, updates.color ?? null, updates.description ?? null]); return result.rows[0] ? this.mapSubjectRow(result.rows[0]) : undefined; });
  }

  async deleteSubjectAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteSubject(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('DELETE FROM subjects WHERE id = $1 AND organization_id = $2', [id, organizationId])).rowCount === 1);
  }

  private courseSelect = `SELECT c.id, c.organization_id, c.subject_id, c.term_id, c.teacher_id, c.classroom_id, c.title, c.description, c.created_at, s.name AS subject_name, u.full_name AS teacher_name, cl.name AS classroom_name FROM courses c JOIN subjects s ON s.id = c.subject_id AND s.organization_id = c.organization_id LEFT JOIN users u ON u.id = c.teacher_id AND u.organization_id = c.organization_id JOIN classrooms cl ON cl.id = c.classroom_id AND cl.organization_id = c.organization_id`;

  async getCoursesAsync(organizationId: string, teacherId?: string, classroomId?: string): Promise<Course[]> {
    if (process.env.NODE_ENV !== 'production') return this.getCourses(organizationId, teacherId, classroomId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query(`${this.courseSelect} WHERE c.organization_id = $1 AND ($2::text IS NULL OR c.teacher_id = $2) AND ($3::text IS NULL OR c.classroom_id = $3) ORDER BY c.title, c.id`, [organizationId, teacherId || null, classroomId || null])).rows.map((row: any) => this.mapCourseRow(row)));
  }

  async getCourseByIdAsync(id: string, organizationId: string): Promise<Course | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getCourseById(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query(`${this.courseSelect} WHERE c.id = $1 AND c.organization_id = $2`, [id, organizationId]); return result.rows[0] ? this.mapCourseRow(result.rows[0]) : undefined; });
  }

  async createCourseAsync(data: Omit<Course, 'id' | 'createdAt' | 'updatedAt'>): Promise<Course> {
    if (process.env.NODE_ENV !== 'production') return this.createCourse(data);
    const id = generateId('crs');
    return this.withIdentityTenant(data.organizationId, async (client) => {
      const result = await client.query(`INSERT INTO courses (id, organization_id, subject_id, term_id, teacher_id, classroom_id, title, description) SELECT $1, $2, $3, $4, $5, $6, $7, $8 WHERE EXISTS (SELECT 1 FROM subjects WHERE id = $3 AND organization_id = $2) AND EXISTS (SELECT 1 FROM terms WHERE id = $4 AND organization_id = $2) AND EXISTS (SELECT 1 FROM classrooms WHERE id = $6 AND organization_id = $2) AND ($5::text IS NULL OR EXISTS (SELECT 1 FROM users WHERE id = $5 AND organization_id = $2 AND role IN ('TEACHER', 'ORG_ADMIN', 'SUPER_ADMIN'))) RETURNING id`, [id, data.organizationId, data.subjectId, data.termId, data.teacherId ?? null, data.classroomId, data.title, data.description ?? null]);
      if (!result.rows[0]) throw new Error('INVALID_COURSE_REFERENCE');
      const courseResult = await client.query(`${this.courseSelect} WHERE c.id = $1 AND c.organization_id = $2`, [id, data.organizationId]);
      return this.mapCourseRow(courseResult.rows[0]);
    });
  }

  async updateCourseAsync(id: string, organizationId: string, updates: Partial<Course>): Promise<Course | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateCourse(id, organizationId, updates);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(`UPDATE courses SET subject_id = COALESCE($3, subject_id), term_id = COALESCE($4, term_id), teacher_id = COALESCE($5, teacher_id), classroom_id = COALESCE($6, classroom_id), title = COALESCE($7, title), description = COALESCE($8, description) WHERE id = $1 AND organization_id = $2 AND ($3::text IS NULL OR EXISTS (SELECT 1 FROM subjects WHERE id = $3 AND organization_id = $2)) AND ($4::text IS NULL OR EXISTS (SELECT 1 FROM terms WHERE id = $4 AND organization_id = $2)) AND ($6::text IS NULL OR EXISTS (SELECT 1 FROM classrooms WHERE id = $6 AND organization_id = $2)) RETURNING id`, [id, organizationId, updates.subjectId ?? null, updates.termId ?? null, updates.teacherId ?? null, updates.classroomId ?? null, updates.title ?? null, updates.description ?? null]);
      if (!result.rows[0]) return undefined;
      const courseResult = await client.query(`${this.courseSelect} WHERE c.id = $1 AND c.organization_id = $2`, [id, organizationId]);
      return courseResult.rows[0] ? this.mapCourseRow(courseResult.rows[0]) : undefined;
    });
  }

  async deleteCourseAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteCourse(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('DELETE FROM courses WHERE id = $1 AND organization_id = $2', [id, organizationId])).rowCount === 1);
  }

  private enrollmentSelect = `SELECT e.id, e.organization_id, e.student_id, u.full_name AS student_name, u.email AS student_email, u.student_id_number, e.classroom_id, cl.name AS classroom_name, cl.grade_level_id, gl.name AS grade_level_name, e.academic_year_id, ay.name AS academic_year_name, e.roll_number, e.status, e.enrolled_at, e.updated_at FROM student_enrollments e JOIN users u ON u.id = e.student_id AND u.organization_id = e.organization_id JOIN classrooms cl ON cl.id = e.classroom_id AND cl.organization_id = e.organization_id JOIN grade_levels gl ON gl.id = cl.grade_level_id AND gl.organization_id = e.organization_id JOIN academic_years ay ON ay.id = e.academic_year_id AND ay.organization_id = e.organization_id`;

  async getStudentEnrollmentsAsync(organizationId: string, filters?: { classroomId?: string; studentId?: string; academicYearId?: string; status?: StudentEnrollmentStatus }): Promise<StudentEnrollment[]> {
    if (process.env.NODE_ENV !== 'production') return this.getStudentEnrollments(organizationId, filters);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query(`${this.enrollmentSelect} WHERE e.organization_id = $1 AND ($2::text IS NULL OR e.classroom_id = $2) AND ($3::text IS NULL OR e.student_id = $3) AND ($4::text IS NULL OR e.academic_year_id = $4) AND ($5::text IS NULL OR e.status = $5) ORDER BY e.enrolled_at, e.id`, [organizationId, filters?.classroomId || null, filters?.studentId || null, filters?.academicYearId || null, filters?.status || null])).rows.map((row: any) => this.mapEnrollmentRow(row)));
  }

  async getStudentEnrollmentByIdAsync(id: string, organizationId: string): Promise<StudentEnrollment | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getStudentEnrollmentById(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query(`${this.enrollmentSelect} WHERE e.id = $1 AND e.organization_id = $2`, [id, organizationId]); return result.rows[0] ? this.mapEnrollmentRow(result.rows[0]) : undefined; });
  }

  async createStudentEnrollmentAsync(data: Omit<StudentEnrollment, 'id' | 'enrolledAt' | 'updatedAt'>): Promise<StudentEnrollment> {
    if (process.env.NODE_ENV !== 'production') return this.createStudentEnrollment(data);
    const id = generateId('enr');
    return this.withIdentityTenant(data.organizationId, async (client) => {
      const result = await client.query('INSERT INTO student_enrollments (id, organization_id, student_id, classroom_id, academic_year_id, roll_number, status) SELECT $1, $2, $3, $4, $5, $6, $7 WHERE EXISTS (SELECT 1 FROM users WHERE id = $3 AND organization_id = $2 AND role = \'STUDENT\') AND EXISTS (SELECT 1 FROM classrooms WHERE id = $4 AND organization_id = $2) AND EXISTS (SELECT 1 FROM academic_years WHERE id = $5 AND organization_id = $2) RETURNING id', [id, data.organizationId, data.studentId, data.classroomId, data.academicYearId, data.rollNumber ?? null, data.status]);
      if (!result.rows[0]) throw new Error('INVALID_ENROLLMENT_REFERENCE');
      const enrollmentResult = await client.query(`${this.enrollmentSelect} WHERE e.id = $1 AND e.organization_id = $2`, [id, data.organizationId]);
      await client.query('UPDATE users SET classroom_id = $3 WHERE id = $1 AND organization_id = $2 AND $4 = \'ACTIVE\'', [data.studentId, data.organizationId, data.classroomId, data.status]);
      return this.mapEnrollmentRow(enrollmentResult.rows[0]);
    });
  }

  async updateStudentEnrollmentAsync(id: string, organizationId: string, updates: Partial<StudentEnrollment>): Promise<StudentEnrollment | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.updateStudentEnrollment(id, organizationId, updates);
    return this.withIdentityTenant(organizationId, async (client) => { const result = await client.query('UPDATE student_enrollments SET classroom_id = COALESCE($3, classroom_id), roll_number = COALESCE($4, roll_number), status = COALESCE($5, status), updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND organization_id = $2 AND ($3::text IS NULL OR EXISTS (SELECT 1 FROM classrooms WHERE id = $3 AND organization_id = $2)) RETURNING id', [id, organizationId, updates.classroomId ?? null, updates.rollNumber ?? null, updates.status ?? null]); if (!result.rows[0]) return undefined; const enrollmentResult = await client.query(`${this.enrollmentSelect} WHERE e.id = $1 AND e.organization_id = $2`, [id, organizationId]); return enrollmentResult.rows[0] ? this.mapEnrollmentRow(enrollmentResult.rows[0]) : undefined; });
  }

  async deleteStudentEnrollmentAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.deleteStudentEnrollment(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => (await client.query('DELETE FROM student_enrollments WHERE id = $1 AND organization_id = $2', [id, organizationId])).rowCount === 1);
  }

  getAcademicYears(organizationId: string): AcademicYear[] {
    return Array.from(this.academicYears.values()).filter((y) => y.organizationId === organizationId);
  }

  getCurrentAcademicYear(organizationId: string): AcademicYear | undefined {
    return Array.from(this.academicYears.values()).find((y) => y.organizationId === organizationId && y.isCurrent);
  }

  getCoursesByClassroom(classroomId: string, organizationId: string): Course[] {
    return Array.from(this.courses.values()).filter(
      (c) => c.organizationId === organizationId && c.classroomId === classroomId
    );
  }

  getAcademicYearById(id: string, organizationId: string): AcademicYear | undefined {
    const item = this.academicYears.get(id);
    if (!item || item.organizationId !== organizationId) return undefined;
    return item;
  }

  createAcademicYear(data: Omit<AcademicYear, 'id'>): AcademicYear {
    const id = `year_${Date.now()}`;
    const item: AcademicYear = { ...data, id };
    if (item.isCurrent) {
      // Set all other academic years in this org to isCurrent = false
      for (const [yId, year] of this.academicYears.entries()) {
        if (year.organizationId === data.organizationId && yId !== id) {
          year.isCurrent = false;
        }
      }
    }
    this.academicYears.set(id, item);
    return item;
  }

  updateAcademicYear(id: string, organizationId: string, updates: Partial<AcademicYear>): AcademicYear | undefined {
    const item = this.getAcademicYearById(id, organizationId);
    if (!item) return undefined;
    if (updates.isCurrent) {
      for (const [yId, year] of this.academicYears.entries()) {
        if (year.organizationId === organizationId && yId !== id) {
          year.isCurrent = false;
        }
      }
    }
    const updated: AcademicYear = { ...item, ...updates };
    this.academicYears.set(id, updated);
    return updated;
  }

  deleteAcademicYear(id: string, organizationId: string): boolean {
    const item = this.getAcademicYearById(id, organizationId);
    if (!item) return false;
    this.academicYears.delete(id);
    return true;
  }

  getTerms(organizationId: string, academicYearId?: string): Term[] {
    return Array.from(this.terms.values()).filter((t) => {
      if (t.organizationId !== organizationId) return false;
      if (academicYearId && t.academicYearId !== academicYearId) return false;
      return true;
    });
  }

  getTermById(id: string, organizationId: string): Term | undefined {
    const item = this.terms.get(id);
    if (!item || item.organizationId !== organizationId) return undefined;
    return item;
  }

  createTerm(data: Omit<Term, 'id'>): Term {
    const id = `term_${Date.now()}`;
    const item: Term = { ...data, id };
    if (item.isCurrent) {
      for (const [tId, term] of this.terms.entries()) {
        if (term.organizationId === data.organizationId && tId !== id) {
          term.isCurrent = false;
        }
      }
    }
    this.terms.set(id, item);
    return item;
  }

  updateTerm(id: string, organizationId: string, updates: Partial<Term>): Term | undefined {
    const item = this.getTermById(id, organizationId);
    if (!item) return undefined;
    if (updates.isCurrent) {
      for (const [tId, term] of this.terms.entries()) {
        if (term.organizationId === organizationId && tId !== id) {
          term.isCurrent = false;
        }
      }
    }
    const updated: Term = { ...item, ...updates };
    this.terms.set(id, updated);
    return updated;
  }

  deleteTerm(id: string, organizationId: string): boolean {
    const item = this.getTermById(id, organizationId);
    if (!item) return false;
    this.terms.delete(id);
    return true;
  }

  getGradeLevels(organizationId: string): GradeLevel[] {
    return Array.from(this.gradeLevels.values())
      .filter((g) => g.organizationId === organizationId)
      .sort((a, b) => a.sequenceOrder - b.sequenceOrder);
  }

  getGradeLevelById(id: string, organizationId: string): GradeLevel | undefined {
    const gl = this.gradeLevels.get(id);
    if (!gl || gl.organizationId !== organizationId) return undefined;
    return gl;
  }

  createGradeLevel(data: Omit<GradeLevel, 'id'>): GradeLevel {
    const id = `grade_${Date.now()}`;
    const item: GradeLevel = { ...data, id };
    this.gradeLevels.set(id, item);
    return item;
  }

  updateGradeLevel(id: string, organizationId: string, updates: Partial<GradeLevel>): GradeLevel | undefined {
    const gl = this.getGradeLevelById(id, organizationId);
    if (!gl) return undefined;
    const updated: GradeLevel = { ...gl, ...updates };
    this.gradeLevels.set(id, updated);
    return updated;
  }

  deleteGradeLevel(id: string, organizationId: string): boolean {
    const gl = this.getGradeLevelById(id, organizationId);
    if (!gl) return false;
    this.gradeLevels.delete(id);
    return true;
  }

  getClassrooms(organizationId: string, gradeLevelId?: string): Classroom[] {
    return Array.from(this.classrooms.values()).filter((c) => {
      if (c.organizationId !== organizationId) return false;
      if (gradeLevelId && c.gradeLevelId !== gradeLevelId) return false;
      return true;
    });
  }

  getClassroomById(id: string, organizationId: string): Classroom | undefined {
    const c = this.classrooms.get(id);
    if (!c || c.organizationId !== organizationId) return undefined;
    return c;
  }

  createClassroom(data: Omit<Classroom, 'id'>): Classroom {
    const id = `class_${Date.now()}`;
    const item: Classroom = { ...data, id };
    this.classrooms.set(id, item);
    return item;
  }

  updateClassroom(id: string, organizationId: string, updates: Partial<Classroom>): Classroom | undefined {
    const c = this.getClassroomById(id, organizationId);
    if (!c) return undefined;
    const updated: Classroom = { ...c, ...updates };
    this.classrooms.set(id, updated);
    return updated;
  }

  deleteClassroom(id: string, organizationId: string): boolean {
    const c = this.getClassroomById(id, organizationId);
    if (!c) return false;
    this.classrooms.delete(id);
    return true;
  }

  getSubjects(organizationId: string): Subject[] {
    return Array.from(this.subjects.values()).filter((s) => s.organizationId === organizationId);
  }

  getSubjectById(id: string, organizationId: string): Subject | undefined {
    const s = this.subjects.get(id);
    if (!s || s.organizationId !== organizationId) return undefined;
    return s;
  }

  createSubject(data: Omit<Subject, 'id'>): Subject {
    const id = generateId('sub');
    const item: Subject = { ...data, id };
    this.subjects.set(id, item);
    return item;
  }

  updateSubject(id: string, organizationId: string, updates: Partial<Subject>): Subject | undefined {
    const s = this.getSubjectById(id, organizationId);
    if (!s) return undefined;
    const updated: Subject = { ...s, ...updates };
    this.subjects.set(id, updated);
    return updated;
  }

  deleteSubject(id: string, organizationId: string): boolean {
    const s = this.getSubjectById(id, organizationId);
    if (!s) return false;
    this.subjects.delete(id);
    return true;
  }

  // Courses
  getCourses(organizationId: string, teacherId?: string, classroomId?: string): Course[] {
    return Array.from(this.courses.values()).filter((c) => {
      if (c.organizationId !== organizationId) return false;
      if (teacherId && c.teacherId !== teacherId) return false;
      if (classroomId && c.classroomId !== classroomId) return false;
      return true;
    });
  }

  getCourseById(courseId: string, organizationId: string): Course | undefined {
    const course = this.courses.get(courseId);
    if (!course || course.organizationId !== organizationId) return undefined;
    return course;
  }

  createCourse(data: Omit<Course, 'id' | 'createdAt' | 'updatedAt'>): Course {
    const id = generateId('crs');
    const subject = data.subjectId ? this.subjects.get(data.subjectId) : undefined;
    const teacher = data.teacherId ? this.users.get(data.teacherId) : undefined;
    const classroom = data.classroomId ? this.classrooms.get(data.classroomId) : undefined;

    const course: Course = {
      ...data,
      id,
      subjectName: subject?.name,
      teacherName: teacher?.fullName,
      classroomName: classroom?.name,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.courses.set(id, course);
    return course;
  }

  updateCourse(id: string, organizationId: string, updates: Partial<Course>): Course | undefined {
    const course = this.getCourseById(id, organizationId);
    if (!course) return undefined;
    const subject = updates.subjectId ? this.subjects.get(updates.subjectId) : undefined;
    const teacher = updates.teacherId ? this.users.get(updates.teacherId) : undefined;
    const classroom = updates.classroomId ? this.classrooms.get(updates.classroomId) : undefined;

    const updated: Course = {
      ...course,
      ...updates,
      subjectName: subject ? subject.name : course.subjectName,
      teacherName: teacher ? teacher.fullName : course.teacherName,
      classroomName: classroom ? classroom.name : course.classroomName,
      updatedAt: new Date().toISOString(),
    };
    this.courses.set(id, updated);
    return updated;
  }

  deleteCourse(id: string, organizationId: string): boolean {
    const course = this.getCourseById(id, organizationId);
    if (!course) return false;
    this.courses.delete(id);
    return true;
  }

  // --- Teacher Assignments ---
  getTeacherAssignments(
    organizationId: string,
    filters?: { teacherId?: string; courseId?: string; classroomId?: string; academicYearId?: string; subjectId?: string }
  ): TeacherAssignment[] {
    return Array.from(this.teacherAssignments.values()).filter((ta) => {
      if (ta.organizationId !== organizationId) return false;
      if (filters?.teacherId && ta.teacherId !== filters.teacherId) return false;
      if (filters?.courseId && ta.courseId !== filters.courseId) return false;
      if (filters?.classroomId && ta.classroomId !== filters.classroomId) return false;
      if (filters?.academicYearId && ta.academicYearId !== filters.academicYearId) return false;
      if (filters?.subjectId && ta.subjectId !== filters.subjectId) return false;
      return true;
    });
  }

  getTeacherAssignmentById(id: string, organizationId: string): TeacherAssignment | undefined {
    const ta = this.teacherAssignments.get(id);
    if (!ta || ta.organizationId !== organizationId) return undefined;
    return ta;
  }

  createTeacherAssignment(
    data: Omit<TeacherAssignment, 'id' | 'createdAt' | 'updatedAt'>
  ): TeacherAssignment {
    const id = `ta_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const teacher = this.getUserById(data.teacherId, data.organizationId);
    const subject = this.getSubjectById(data.subjectId, data.organizationId);
    const classroom = this.getClassroomById(data.classroomId, data.organizationId);
    const course = data.courseId ? this.getCourseById(data.courseId, data.organizationId) : undefined;
    const year = data.academicYearId ? this.getAcademicYearById(data.academicYearId, data.organizationId) : undefined;

    const now = new Date().toISOString();
    const assignment: TeacherAssignment = {
      ...data,
      id,
      teacherName: teacher?.fullName,
      teacherEmail: teacher?.email,
      subjectName: subject?.name,
      classroomName: classroom?.name,
      courseTitle: course?.title,
      academicYearName: year?.name,
      createdAt: now,
      updatedAt: now,
    };
    this.teacherAssignments.set(id, assignment);
    return assignment;
  }

  updateTeacherAssignment(
    id: string,
    organizationId: string,
    updates: Partial<TeacherAssignment>
  ): TeacherAssignment | undefined {
    const ta = this.getTeacherAssignmentById(id, organizationId);
    if (!ta) return undefined;
    const teacher = updates.teacherId ? this.getUserById(updates.teacherId, organizationId) : undefined;
    const subject = updates.subjectId ? this.getSubjectById(updates.subjectId, organizationId) : undefined;
    const classroom = updates.classroomId ? this.getClassroomById(updates.classroomId, organizationId) : undefined;

    const updated: TeacherAssignment = {
      ...ta,
      ...updates,
      teacherName: teacher ? teacher.fullName : ta.teacherName,
      teacherEmail: teacher ? teacher.email : ta.teacherEmail,
      subjectName: subject ? subject.name : ta.subjectName,
      classroomName: classroom ? classroom.name : ta.classroomName,
      updatedAt: new Date().toISOString(),
    };
    this.teacherAssignments.set(id, updated);
    return updated;
  }

  deleteTeacherAssignment(id: string, organizationId: string): boolean {
    const ta = this.getTeacherAssignmentById(id, organizationId);
    if (!ta) return false;
    this.teacherAssignments.delete(id);
    return true;
  }

  // --- Student Enrollments ---
  getStudentEnrollments(
    organizationId: string,
    filters?: { classroomId?: string; studentId?: string; academicYearId?: string; status?: StudentEnrollmentStatus }
  ): StudentEnrollment[] {
    return Array.from(this.studentEnrollments.values()).filter((enr) => {
      if (enr.organizationId !== organizationId) return false;
      if (filters?.classroomId && enr.classroomId !== filters.classroomId) return false;
      if (filters?.studentId && enr.studentId !== filters.studentId) return false;
      if (filters?.academicYearId && enr.academicYearId !== filters.academicYearId) return false;
      if (filters?.status && enr.status !== filters.status) return false;
      return true;
    });
  }

  getStudentEnrollmentById(id: string, organizationId: string): StudentEnrollment | undefined {
    const enr = this.studentEnrollments.get(id);
    if (!enr || enr.organizationId !== organizationId) return undefined;
    return enr;
  }

  createStudentEnrollment(
    data: Omit<StudentEnrollment, 'id' | 'enrolledAt' | 'updatedAt'>
  ): StudentEnrollment {
    const id = `enr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const student = this.getUserById(data.studentId, data.organizationId);
    const classroom = this.getClassroomById(data.classroomId, data.organizationId);
    const gradeLevel = classroom ? this.getGradeLevelById(classroom.gradeLevelId, data.organizationId) : undefined;
    const year = this.getAcademicYearById(data.academicYearId, data.organizationId);

    const now = new Date().toISOString();
    const enrollment: StudentEnrollment = {
      ...data,
      id,
      studentName: student?.fullName,
      studentEmail: student?.email,
      studentIdNumber: student?.studentIdNumber,
      classroomName: classroom?.name,
      gradeLevelId: classroom?.gradeLevelId,
      gradeLevelName: gradeLevel?.name,
      academicYearName: year?.name,
      enrolledAt: now,
      updatedAt: now,
    };
    this.studentEnrollments.set(id, enrollment);

    // Sync classroomId onto student user if active
    if (student && data.classroomId) {
      this.updateUser(student.id, data.organizationId, { classroomId: data.classroomId });
    }

    return enrollment;
  }

  updateStudentEnrollment(
    id: string,
    organizationId: string,
    updates: Partial<StudentEnrollment>
  ): StudentEnrollment | undefined {
    const enr = this.getStudentEnrollmentById(id, organizationId);
    if (!enr) return undefined;
    const classroom = updates.classroomId ? this.getClassroomById(updates.classroomId, organizationId) : undefined;
    const gradeLevel = classroom ? this.getGradeLevelById(classroom.gradeLevelId, organizationId) : undefined;

    const updated: StudentEnrollment = {
      ...enr,
      ...updates,
      classroomName: classroom ? classroom.name : enr.classroomName,
      gradeLevelId: classroom ? classroom.gradeLevelId : enr.gradeLevelId,
      gradeLevelName: gradeLevel ? gradeLevel.name : enr.gradeLevelName,
      updatedAt: new Date().toISOString(),
    };
    this.studentEnrollments.set(id, updated);
    return updated;
  }

  deleteStudentEnrollment(id: string, organizationId: string): boolean {
    const enr = this.getStudentEnrollmentById(id, organizationId);
    if (!enr) return false;
    this.studentEnrollments.delete(id);
    return true;
  }

  getStudentsByClassroom(classroomId: string, organizationId: string): User[] {
    const enrollments = this.getStudentEnrollments(organizationId, { classroomId, status: 'ACTIVE' });
    const students: User[] = [];
    for (const enr of enrollments) {
      const u = this.getUserById(enr.studentId, organizationId);
      if (u) students.push(u);
    }
    // Also include any users directly tagged with classroomId
    const directUsers = Array.from(this.users.values()).filter(
      (u) => u.organizationId === organizationId && u.role === 'STUDENT' && u.classroomId === classroomId
    );
    for (const du of directUsers) {
      if (!students.some((s) => s.id === du.id)) {
        students.push(du);
      }
    }
    return students;
  }

  // --- Parent Student Links ---
  getParentStudentLinks(
    organizationId: string,
    filters?: { parentId?: string; studentId?: string }
  ): ParentStudentLink[] {
    return Array.from(this.parentStudentLinks.values()).filter((link) => {
      if (link.organizationId !== organizationId) return false;
      if (filters?.parentId && link.parentId !== filters.parentId) return false;
      if (filters?.studentId && link.studentId !== filters.studentId) return false;
      return true;
    });
  }

  createParentStudentLink(
    data: Omit<ParentStudentLink, 'id' | 'createdAt'>
  ): ParentStudentLink {
    const id = `psl_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const parent = this.getUserById(data.parentId, data.organizationId);
    const student = this.getUserById(data.studentId, data.organizationId);

    const link: ParentStudentLink = {
      ...data,
      id,
      parentName: parent?.fullName,
      studentName: student?.fullName,
      createdAt: new Date().toISOString(),
    };
    this.parentStudentLinks.set(id, link);
    return link;
  }

  deleteParentStudentLink(id: string, organizationId: string): boolean {
    const link = this.parentStudentLinks.get(id);
    if (!link || link.organizationId !== organizationId) return false;
    this.parentStudentLinks.delete(id);
    return true;
  }

  // --- Student Records (Full SIS Profile, Demographics, Medical & Emergency) ---
  getStudentRecords(
    organizationId: string,
    filters?: { status?: StudentLifecycleStatus; search?: string; studentId?: string }
  ): StudentRecord[] {
    return Array.from(this.studentRecords.values()).filter((rec) => {
      if (rec.organizationId !== organizationId) return false;
      if (filters?.status && rec.status !== filters.status) return false;
      if (filters?.studentId && rec.studentId !== filters.studentId) return false;
      if (filters?.search) {
        const q = filters.search.toLowerCase().trim();
        const user = this.getUserById(rec.studentId, organizationId);
        const matchName = user?.fullName.toLowerCase().includes(q);
        const matchEmail = user?.email.toLowerCase().includes(q);
        const matchNationalId = rec.nationalId.toLowerCase().includes(q);
        const matchStdId = user?.studentIdNumber?.toLowerCase().includes(q);
        if (!matchName && !matchEmail && !matchNationalId && !matchStdId) return false;
      }
      return true;
    });
  }

  getStudentRecordById(id: string, organizationId: string): StudentRecord | undefined {
    const rec = this.studentRecords.get(id);
    if (!rec || rec.organizationId !== organizationId) return undefined;
    return rec;
  }

  getStudentRecordByStudentId(studentId: string, organizationId: string): StudentRecord | undefined {
    return Array.from(this.studentRecords.values()).find(
      (rec) => rec.organizationId === organizationId && rec.studentId === studentId
    );
  }

  getStudentRecordByNationalId(nationalId: string, organizationId: string): StudentRecord | undefined {
    return Array.from(this.studentRecords.values()).find(
      (rec) => rec.organizationId === organizationId && rec.nationalId === nationalId
    );
  }

  createStudentRecord(
    data: Omit<StudentRecord, 'id' | 'createdAt' | 'updatedAt'>
  ): StudentRecord {
    const id = `std_rec_${data.studentId}`;
    const now = new Date().toISOString();
    const record: StudentRecord = {
      ...data,
      id,
      createdAt: now,
      updatedAt: now,
    };
    this.studentRecords.set(id, record);
    return record;
  }

  updateStudentRecord(
    studentId: string,
    organizationId: string,
    updates: Partial<StudentRecord>
  ): StudentRecord | undefined {
    const rec = this.getStudentRecordByStudentId(studentId, organizationId);
    if (!rec) return undefined;

    const updated: StudentRecord = {
      ...rec,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.studentRecords.set(rec.id, updated);
    return updated;
  }

  deleteStudentRecord(studentId: string, organizationId: string): boolean {
    const rec = this.getStudentRecordByStudentId(studentId, organizationId);
    if (!rec) return false;
    this.studentRecords.delete(rec.id);
    return true;
  }

  // --- Student Behavior & Merit Records ---
  getStudentBehaviorRecords(
    organizationId: string,
    filters?: { studentId?: string; type?: StudentBehaviorType; status?: string }
  ): StudentBehaviorRecord[] {
    return Array.from(this.studentBehaviorRecords.values())
      .filter((beh) => {
        if (beh.organizationId !== organizationId) return false;
        if (filters?.studentId && beh.studentId !== filters.studentId) return false;
        if (filters?.type && beh.type !== filters.type) return false;
        if (filters?.status && beh.status !== filters.status) return false;
        return true;
      })
      .sort((a, b) => new Date(b.incidentDate).getTime() - new Date(a.incidentDate).getTime());
  }

  getStudentBehaviorRecordById(id: string, organizationId: string): StudentBehaviorRecord | undefined {
    const beh = this.studentBehaviorRecords.get(id);
    if (!beh || beh.organizationId !== organizationId) return undefined;
    return beh;
  }

  createStudentBehaviorRecord(
    data: Omit<StudentBehaviorRecord, 'id' | 'createdAt'>
  ): StudentBehaviorRecord {
    const id = `beh_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const student = this.getUserById(data.studentId, data.organizationId);
    const recordedByUser = this.getUserById(data.recordedBy, data.organizationId);

    const record: StudentBehaviorRecord = {
      ...data,
      id,
      studentName: student?.fullName,
      recordedByName: recordedByUser?.fullName,
      createdAt: new Date().toISOString(),
    };
    this.studentBehaviorRecords.set(id, record);
    return record;
  }

  updateStudentBehaviorRecord(
    id: string,
    organizationId: string,
    updates: Partial<StudentBehaviorRecord>
  ): StudentBehaviorRecord | undefined {
    const beh = this.getStudentBehaviorRecordById(id, organizationId);
    if (!beh) return undefined;

    const updated: StudentBehaviorRecord = {
      ...beh,
      ...updates,
    };
    this.studentBehaviorRecords.set(id, updated);
    return updated;
  }

  deleteStudentBehaviorRecord(id: string, organizationId: string): boolean {
    const beh = this.getStudentBehaviorRecordById(id, organizationId);
    if (!beh) return false;
    this.studentBehaviorRecords.delete(id);
    return true;
  }

  // --- Student Lifecycle Events ---
  getStudentLifecycleEvents(organizationId: string, studentId?: string): StudentLifecycleEvent[] {
    return Array.from(this.studentLifecycleEvents.values())
      .filter((ev) => {
        if (ev.organizationId !== organizationId) return false;
        if (studentId && ev.studentId !== studentId) return false;
        return true;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  createStudentLifecycleEvent(
    data: Omit<StudentLifecycleEvent, 'id' | 'timestamp'>
  ): StudentLifecycleEvent {
    const id = `lce_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const student = this.getUserById(data.studentId, data.organizationId);
    const actionUser = this.getUserById(data.actionBy, data.organizationId);

    const event: StudentLifecycleEvent = {
      ...data,
      id,
      studentName: student?.fullName,
      actionByName: actionUser?.fullName,
      timestamp: new Date().toISOString(),
    };
    this.studentLifecycleEvents.set(id, event);
    return event;
  }

  // --- Comprehensive Student Dossier (Holistic SIS Record) ---
  getStudentDossier(studentId: string, organizationId: string): StudentDossier | null {
    const student = this.getUserById(studentId, organizationId);
    if (!student || student.role !== 'STUDENT') return null;

    const record = this.getStudentRecordByStudentId(studentId, organizationId);
    const enrollments = this.getStudentEnrollments(organizationId, { studentId });
    const currentEnrollment = enrollments.find((e) => e.status === 'ACTIVE') || enrollments[0];
    const parents = this.getParentStudentLinks(organizationId, { studentId });
    const behaviorRecords = this.getStudentBehaviorRecords(organizationId, { studentId });
    const behaviorPointsTotal = behaviorRecords.reduce((acc, r) => acc + (r.points || 0), 0);

    // Attendance stats
    const studentAttendance = Array.from(this.attendanceRecords.values()).filter(
      (a) => a.organizationId === organizationId && a.studentId === studentId
    );
    const totalDays = studentAttendance.length;
    const presentDays = studentAttendance.filter((a) => a.status === 'PRESENT').length;
    const absentDays = studentAttendance.filter((a) => a.status === 'ABSENT').length;
    const lateDays = studentAttendance.filter((a) => a.status === 'LATE').length;
    const excusedDays = studentAttendance.filter((a) => a.status === 'EXCUSED').length;
    const attendanceRate = totalDays > 0 ? Math.round(((presentDays + lateDays + excusedDays) / totalDays) * 100) : 100;

    // Academic performance stats
    const submissions = this.getSubmissionsByStudent(studentId, organizationId);
    const courses = student.classroomId ? this.getCoursesByClassroom(student.classroomId, organizationId) : [];
    let scoreSum = 0;
    let gradedCount = 0;
    for (const sub of submissions) {
      if (typeof sub.score === 'number') {
        const assignment = this.getAssignmentById(sub.assignmentId, organizationId);
        const maxScore = assignment?.maxScore || 100;
        scoreSum += (sub.score / maxScore) * 100;
        gradedCount++;
      }
    }
    const averageScore = gradedCount > 0 ? Math.round(scoreSum / gradedCount) : 92;

    const lifecycleHistory = this.getStudentLifecycleEvents(organizationId, studentId);

    return {
      student,
      record,
      enrollments,
      currentEnrollment,
      parents,
      behaviorRecords,
      behaviorPointsTotal,
      attendanceStats: {
        totalDays,
        presentDays,
        absentDays,
        lateDays,
        excusedDays,
        attendanceRate,
      },
      academicStats: {
        enrolledCoursesCount: courses.length,
        submissionsCount: submissions.length,
        averageScore,
      },
      lifecycleHistory,
    };
  }

  // Lessons
  getLessonsByCourse(courseId: string, organizationId: string): Lesson[] {
    return Array.from(this.lessons.values())
      .filter((l) => l.organizationId === organizationId && l.courseId === courseId)
      .sort((a, b) => a.orderIndex - b.orderIndex);
  }

  getLessonById(lessonId: string, organizationId: string): Lesson | undefined {
    const lesson = this.lessons.get(lessonId);
    if (!lesson || lesson.organizationId !== organizationId) return undefined;
    return lesson;
  }

  createLesson(data: Omit<Lesson, 'id' | 'createdAt' | 'updatedAt'>): Lesson {
    const id = generateId('les');
    const now = new Date().toISOString();
    const lesson: Lesson = { ...data, id, createdAt: now, updatedAt: now };
    this.lessons.set(id, lesson);
    return lesson;
  }

  updateLesson(id: string, organizationId: string, updates: Partial<Lesson>): Lesson | undefined {
    const lesson = this.getLessonById(id, organizationId);
    if (!lesson) return undefined;
    const updated: Lesson = { ...lesson, ...updates, updatedAt: new Date().toISOString() };
    this.lessons.set(id, updated);
    return updated;
  }

  deleteLesson(id: string, organizationId: string): boolean {
    const lesson = this.getLessonById(id, organizationId);
    if (!lesson) return false;
    this.lessons.delete(id);
    return true;
  }

  // Assignments
  getAssignmentsByCourse(courseId: string, organizationId: string): Assignment[] {
    return Array.from(this.assignments.values()).filter(
      (a) => a.organizationId === organizationId && a.courseId === courseId
    );
  }

  getAssignmentsByOrg(organizationId: string): Assignment[] {
    return Array.from(this.assignments.values()).filter((a) => a.organizationId === organizationId);
  }

  getAssignmentById(id: string, organizationId: string): Assignment | undefined {
    const asg = this.assignments.get(id);
    if (!asg || asg.organizationId !== organizationId) return undefined;
    return asg;
  }

  createAssignment(data: Omit<Assignment, 'id' | 'createdAt'>): Assignment {
    const id = `asg_${Date.now()}`;
    const asg: Assignment = { ...data, id, createdAt: new Date().toISOString() };
    this.assignments.set(id, asg);
    return asg;
  }

  // Submissions
  getSubmissionsByAssignment(assignmentId: string, organizationId: string): Submission[] {
    return Array.from(this.submissions.values()).filter(
      (s) => s.organizationId === organizationId && s.assignmentId === assignmentId
    );
  }

  getSubmissionByStudent(assignmentId: string, studentId: string, organizationId: string): Submission | undefined {
    return Array.from(this.submissions.values()).find(
      (s) => s.organizationId === organizationId && s.assignmentId === assignmentId && s.studentId === studentId
    );
  }

  getSubmissionsByStudent(studentId: string, organizationId: string): Submission[] {
    return Array.from(this.submissions.values()).filter(
      (s) => s.organizationId === organizationId && s.studentId === studentId
    );
  }

  submitAssignment(data: Omit<Submission, 'id' | 'submittedAt'>): Submission {
    const existing = this.getSubmissionByStudent(data.assignmentId, data.studentId, data.organizationId);
    const now = new Date().toISOString();
    const student = this.getUserById(data.studentId, data.organizationId);

    if (existing) {
      const updated: Submission = {
        ...existing,
        submissionText: data.submissionText,
        fileAttachmentUrl: data.fileAttachmentUrl,
        submittedAt: now,
      };
      this.submissions.set(existing.id, updated);
      return updated;
    }

    const id = `sub_${Date.now()}`;
    const sub: Submission = {
      ...data,
      id,
      studentName: student?.fullName,
      submittedAt: now,
    };
    this.submissions.set(id, sub);
    return sub;
  }

  gradeSubmission(
    submissionId: string,
    organizationId: string,
    score: number,
    teacherFeedback?: string
  ): Submission | undefined {
    const sub = this.submissions.get(submissionId);
    if (!sub || sub.organizationId !== organizationId) return undefined;
    const updated: Submission = {
      ...sub,
      score,
      teacherFeedback,
      gradedAt: new Date().toISOString(),
    };
    this.submissions.set(submissionId, updated);
    return updated;
  }

  // --- Attendance Sessions & Roll Calls ---
  async syncAcademicDataFromPostgres(organizationId?: string): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) return;

    try {
      // 1. Sync Attendance Sessions
      let sessionsQuery = 'SELECT * FROM attendance_sessions';
      const sessionsParams: any[] = [];
      if (organizationId) {
        sessionsQuery += ' WHERE organization_id = $1';
        sessionsParams.push(organizationId);
      }
      const sessRes = await pool.query(sessionsQuery, sessionsParams);
      for (const row of sessRes.rows) {
        const classroom = this.getClassroomById(row.classroom_id, row.organization_id);
        const course = row.course_id ? this.getCourseById(row.course_id, row.organization_id) : undefined;
        const openedUser = this.getUserById(row.opened_by, row.organization_id);
        const session: AttendanceSession = {
          id: row.id,
          organizationId: row.organization_id,
          classroomId: row.classroom_id,
          classroomName: classroom?.name,
          courseId: row.course_id || undefined,
          courseTitle: course?.title,
          date: row.date ? new Date(row.date).toISOString().split('T')[0] : row.date,
          periodNumber: row.period_number || undefined,
          title: row.title || undefined,
          status: row.status,
          openedBy: row.opened_by,
          openedByName: openedUser?.fullName,
          presentCount: Number(row.present_count) || 0,
          absentCount: Number(row.absent_count) || 0,
          lateCount: Number(row.late_count) || 0,
          excusedCount: Number(row.excused_count) || 0,
          totalStudents: Number(row.total_students) || 0,
          createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : (row.created_at || new Date().toISOString()),
          updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : (row.updated_at || new Date().toISOString()),
        };
        this.attendanceSessions.set(session.id, session);
      }

      // 2. Sync Attendance Records
      let recordsQuery = 'SELECT * FROM attendance_records';
      const recordsParams: any[] = [];
      if (organizationId) {
        recordsQuery += ' WHERE organization_id = $1';
        recordsParams.push(organizationId);
      }
      const recsRes = await pool.query(recordsQuery, recordsParams);
      for (const row of recsRes.rows) {
        const student = this.getUserById(row.student_id, row.organization_id);
        const classroom = this.getClassroomById(row.classroom_id, row.organization_id);
        const recordedUser = row.recorded_by ? this.getUserById(row.recorded_by, row.organization_id) : undefined;
        const record: AttendanceRecord = {
          id: row.id,
          organizationId: row.organization_id,
          sessionId: row.session_id || undefined,
          courseId: row.course_id || undefined,
          classroomId: row.classroom_id,
          classroomName: classroom?.name,
          studentId: row.student_id,
          studentName: student?.fullName,
          studentIdNumber: student?.studentIdNumber,
          recordedBy: row.recorded_by || undefined,
          recordedByName: recordedUser?.fullName,
          date: row.date ? new Date(row.date).toISOString().split('T')[0] : row.date,
          status: row.status,
          notes: row.notes || undefined,
          createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : (row.created_at || new Date().toISOString()),
          updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : (row.updated_at || new Date().toISOString()),
        };
        this.attendanceRecords.set(record.id, record);
      }

      // 3. Sync Assessments
      let assessmentsQuery = 'SELECT * FROM assessments';
      const assessmentsParams: any[] = [];
      if (organizationId) {
        assessmentsQuery += ' WHERE organization_id = $1';
        assessmentsParams.push(organizationId);
      }
      const assRes = await pool.query(assessmentsQuery, assessmentsParams);
      for (const row of assRes.rows) {
        const course = this.getCourseById(row.course_id, row.organization_id);
        const subject = row.subject_id ? this.getSubjectById(row.subject_id, row.organization_id) : course ? this.getSubjectById(course.subjectId, row.organization_id) : undefined;
        const classroom = row.classroom_id ? this.getClassroomById(row.classroom_id, row.organization_id) : course?.classroomId ? this.getClassroomById(course.classroomId, row.organization_id) : undefined;
        const term = row.term_id ? this.getTermById(row.term_id, row.organization_id) : course?.termId ? this.getTermById(course.termId, row.organization_id) : undefined;
        const creator = row.created_by ? this.getUserById(row.created_by, row.organization_id) : undefined;

        const assessment: Assessment = {
          id: row.id,
          organizationId: row.organization_id,
          courseId: row.course_id,
          courseTitle: course?.title,
          subjectId: row.subject_id || course?.subjectId,
          subjectName: subject?.name || course?.subjectName,
          classroomId: row.classroom_id || course?.classroomId,
          classroomName: classroom?.name || course?.classroomName,
          termId: row.term_id || course?.termId,
          termName: term?.name,
          academicYearId: row.academic_year_id || undefined,
          title: row.title,
          description: row.description || undefined,
          category: row.category,
          maxScore: Number(row.max_score) || 100,
          weightPercentage: Number(row.weight_percentage) || 100,
          dueDate: row.due_date?.toISOString ? row.due_date.toISOString() : row.due_date,
          assessmentDate: row.assessment_date ? new Date(row.assessment_date).toISOString().split('T')[0] : row.assessment_date,
          status: row.status,
          createdBy: row.created_by || undefined,
          createdByName: creator?.fullName,
          createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : (row.created_at || new Date().toISOString()),
          updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : (row.updated_at || new Date().toISOString()),
        };
        this.assessments.set(assessment.id, assessment);
      }

      // 4. Sync Assessment Grades
      let gradesQuery = 'SELECT * FROM assessment_grades';
      const gradesParams: any[] = [];
      if (organizationId) {
        gradesQuery += ' WHERE organization_id = $1';
        gradesParams.push(organizationId);
      }
      const gradesRes = await pool.query(gradesQuery, gradesParams);
      for (const row of gradesRes.rows) {
        const student = this.getUserById(row.student_id, row.organization_id);
        const assessment = this.getAssessmentById(row.assessment_id, row.organization_id);
        const grader = row.graded_by ? this.getUserById(row.graded_by, row.organization_id) : undefined;
        const maxScore = assessment?.maxScore || 100;
        const score = Number(row.score) || 0;
        const percentage = maxScore > 0 ? Number(((score / maxScore) * 100).toFixed(2)) : 0;

        const grade: AssessmentGrade = {
          id: row.id,
          organizationId: row.organization_id,
          assessmentId: row.assessment_id,
          assessmentTitle: assessment?.title,
          studentId: row.student_id,
          studentName: student?.fullName,
          studentIdNumber: student?.studentIdNumber,
          score,
          maxScore,
          percentage,
          feedback: row.feedback || undefined,
          gradedBy: row.graded_by || undefined,
          gradedByName: grader?.fullName,
          gradedAt: row.graded_at?.toISOString ? row.graded_at.toISOString() : (row.graded_at || new Date().toISOString()),
          updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : (row.updated_at || new Date().toISOString()),
        };
        this.assessmentGrades.set(grade.id, grade);
      }
    } catch (err) {
      if (process.env.NODE_ENV === 'production') {
        throw err;
      }
      console.error('[PostgreSQL Academic Sync Warning]:', (err as Error).message);
    }
  }

  private async persistAttendanceSessionToPostgres(session: AttendanceSession): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query(
      `INSERT INTO attendance_sessions (
        id, organization_id, classroom_id, course_id, date, period_number, title, status, opened_by, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (id) DO UPDATE SET
        classroom_id = EXCLUDED.classroom_id,
        course_id = EXCLUDED.course_id,
        date = EXCLUDED.date,
        period_number = EXCLUDED.period_number,
        title = EXCLUDED.title,
        status = EXCLUDED.status,
        updated_at = EXCLUDED.updated_at;`,
      [
        session.id,
        session.organizationId,
        session.classroomId,
        session.courseId || null,
        session.date,
        session.periodNumber || 1,
        session.title || null,
        session.status,
        session.openedBy,
        session.createdAt,
        session.updatedAt,
      ]
      );
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        console.error('[PostgreSQL Critical Error]: Failed to persist attendance session', err);
        throw err;
      }
      console.error('[PostgreSQL Session Persist Warning]:', err.message);
    }
  }

  private async deleteAttendanceSessionFromPostgres(id: string, organizationId: string): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query('DELETE FROM attendance_sessions WHERE id = $1 AND organization_id = $2', [id, organizationId]);
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        throw err;
      }
      console.error('[PostgreSQL Delete Session Warning]:', err.message);
    }
  }

  private async persistAttendanceRecordToPostgres(rec: AttendanceRecord): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query(
      `INSERT INTO attendance_records (
        id, organization_id, session_id, course_id, classroom_id, student_id, recorded_by, date, status, notes, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT (id) DO UPDATE SET
        session_id = EXCLUDED.session_id,
        status = EXCLUDED.status,
        notes = EXCLUDED.notes,
        recorded_by = EXCLUDED.recorded_by,
        updated_at = EXCLUDED.updated_at;`,
      [
        rec.id,
        rec.organizationId,
        rec.sessionId || null,
        rec.courseId || null,
        rec.classroomId,
        rec.studentId,
        rec.recordedBy || null,
        rec.date,
        rec.status,
        rec.notes || null,
        rec.createdAt,
        rec.updatedAt,
      ]
      );
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        console.error('[PostgreSQL Critical Error]: Failed to persist attendance record', err);
        throw err;
      }
      console.error('[PostgreSQL Record Persist Warning]:', err.message);
    }
  }

  private async persistAssessmentToPostgres(assessment: Assessment): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query(
      `INSERT INTO assessments (
        id, organization_id, course_id, subject_id, classroom_id, term_id, academic_year_id,
        title, description, category, max_score, weight_percentage, due_date, assessment_date,
        status, created_by, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      ON CONFLICT (id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        max_score = EXCLUDED.max_score,
        weight_percentage = EXCLUDED.weight_percentage,
        due_date = EXCLUDED.due_date,
        assessment_date = EXCLUDED.assessment_date,
        status = EXCLUDED.status,
        updated_at = EXCLUDED.updated_at;`,
      [
        assessment.id,
        assessment.organizationId,
        assessment.courseId,
        assessment.subjectId || null,
        assessment.classroomId || null,
        assessment.termId || null,
        assessment.academicYearId || null,
        assessment.title,
        assessment.description || null,
        assessment.category,
        assessment.maxScore,
        assessment.weightPercentage,
        assessment.dueDate || null,
        assessment.assessmentDate || null,
        assessment.status,
        assessment.createdBy || null,
        assessment.createdAt,
        assessment.updatedAt,
      ]
      );
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        console.error('[PostgreSQL Critical Error]: Failed to persist assessment', err);
        throw err;
      }
      console.error('[PostgreSQL Assessment Persist Warning]:', err.message);
    }
  }

  private async deleteAssessmentFromPostgres(id: string, organizationId: string): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query('DELETE FROM assessments WHERE id = $1 AND organization_id = $2', [id, organizationId]);
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        throw err;
      }
      console.error('[PostgreSQL Delete Assessment Warning]:', err.message);
    }
  }

  private async persistAssessmentGradeToPostgres(grade: AssessmentGrade): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query(
      `INSERT INTO assessment_grades (
        id, organization_id, assessment_id, student_id, score, feedback, graded_by, graded_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (id) DO UPDATE SET
        score = EXCLUDED.score,
        feedback = EXCLUDED.feedback,
        graded_by = EXCLUDED.graded_by,
        graded_at = EXCLUDED.graded_at,
        updated_at = EXCLUDED.updated_at;`,
      [
        grade.id,
        grade.organizationId,
        grade.assessmentId,
        grade.studentId,
        grade.score,
        grade.feedback || null,
        grade.gradedBy || null,
        grade.gradedAt,
        grade.updatedAt,
      ]
      );
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        console.error('[PostgreSQL Critical Error]: Failed to persist assessment grade', err);
        throw err;
      }
      console.error('[PostgreSQL Grade Persist Warning]:', err.message);
    }
  }

  private async deleteAssessmentGradeFromPostgres(id: string, organizationId: string): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query('DELETE FROM assessment_grades WHERE id = $1 AND organization_id = $2', [id, organizationId]);
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        throw err;
      }
      console.error('[PostgreSQL Delete Grade Warning]:', err.message);
    }
  }

  getAttendanceSessions(
    organizationId: string,
    filters?: { classroomId?: string; courseId?: string; date?: string; status?: AttendanceSessionStatus }
  ): AttendanceSession[] {
    return Array.from(this.attendanceSessions.values())
      .filter((s) => {
        if (s.organizationId !== organizationId) return false;
        if (filters?.classroomId && s.classroomId !== filters.classroomId) return false;
        if (filters?.courseId && s.courseId !== filters.courseId) return false;
        if (filters?.date && s.date !== filters.date) return false;
        if (filters?.status && s.status !== filters.status) return false;
        return true;
      })
      .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  }

  getAttendanceSessionById(id: string, organizationId: string): AttendanceSession | undefined {
    const s = this.attendanceSessions.get(id);
    if (!s || s.organizationId !== organizationId) return undefined;
    return s;
  }

  async createAttendanceSession(
    data: Omit<AttendanceSession, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<AttendanceSession> {
    const id = `att_sess_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const classroom = this.getClassroomById(data.classroomId, data.organizationId);
    const course = data.courseId ? this.getCourseById(data.courseId, data.organizationId) : undefined;
    const openedUser = this.getUserById(data.openedBy, data.organizationId);

    const now = new Date().toISOString();
    const session: AttendanceSession = {
      ...data,
      id,
      classroomName: classroom?.name,
      courseTitle: course?.title,
      openedByName: openedUser?.fullName,
      presentCount: data.presentCount || 0,
      absentCount: data.absentCount || 0,
      lateCount: data.lateCount || 0,
      excusedCount: data.excusedCount || 0,
      totalStudents: data.totalStudents || 0,
      createdAt: now,
      updatedAt: now,
    };
    await this.persistAttendanceSessionToPostgres(session);
    this.attendanceSessions.set(id, session);
    return session;
  }

  async updateAttendanceSession(
    id: string,
    organizationId: string,
    updates: Partial<AttendanceSession>
  ): Promise<AttendanceSession | undefined> {
    const s = this.getAttendanceSessionById(id, organizationId);
    if (!s) return undefined;

    const updated: AttendanceSession = {
      ...s,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    await this.persistAttendanceSessionToPostgres(updated);
    this.attendanceSessions.set(id, updated);
    return updated;
  }

  async deleteAttendanceSession(id: string, organizationId: string): Promise<boolean> {
    const s = this.getAttendanceSessionById(id, organizationId);
    if (!s) return false;
    await this.deleteAttendanceSessionFromPostgres(id, organizationId);
    this.attendanceSessions.delete(id);
    // Delete linked attendance records or unlink them
    for (const [recId, rec] of this.attendanceRecords.entries()) {
      if (rec.organizationId === organizationId && rec.sessionId === id) {
        this.attendanceRecords.delete(recId);
      }
    }
    return true;
  }

  // --- Attendance Records ---
  getAttendanceRecords(
    organizationId: string,
    filters?: { sessionId?: string; courseId?: string; classroomId?: string; studentId?: string; date?: string; status?: string }
  ): AttendanceRecord[] {
    return Array.from(this.attendanceRecords.values()).filter((r) => {
      if (r.organizationId !== organizationId) return false;
      if (filters?.sessionId && r.sessionId !== filters.sessionId) return false;
      if (filters?.courseId && r.courseId !== filters.courseId) return false;
      if (filters?.classroomId && r.classroomId !== filters.classroomId) return false;
      if (filters?.studentId && r.studentId !== filters.studentId) return false;
      if (filters?.date && r.date !== filters.date) return false;
      if (filters?.status && r.status !== filters.status) return false;
      return true;
    });
  }

  // Legacy alias
  getAttendance(organizationId: string, courseId?: string, classroomId?: string, date?: string): AttendanceRecord[] {
    return this.getAttendanceRecords(organizationId, { courseId, classroomId, date });
  }

  getAttendanceRecordById(id: string, organizationId: string): AttendanceRecord | undefined {
    const r = this.attendanceRecords.get(id);
    if (!r || r.organizationId !== organizationId) return undefined;
    return r;
  }

  async recordAttendanceBatch(
    organizationId: string,
    records: Omit<AttendanceRecord, 'id' | 'createdAt'>[],
    sessionId?: string
  ): Promise<AttendanceRecord[]> {
    const saved: AttendanceRecord[] = [];
    const now = new Date().toISOString();

    let present = 0;
    let absent = 0;
    let late = 0;
    let excused = 0;

    for (const rec of records) {
      const key = `att_${rec.courseId || rec.classroomId}_${rec.studentId}_${rec.date}`;
      const student = this.getUserById(rec.studentId, organizationId);
      const classroom = this.getClassroomById(rec.classroomId, organizationId);
      const recordedUser = rec.recordedBy ? this.getUserById(rec.recordedBy, organizationId) : undefined;

      const entry: AttendanceRecord = {
        ...rec,
        id: key,
        organizationId,
        sessionId: sessionId || rec.sessionId,
        studentName: student?.fullName || rec.studentName,
        studentIdNumber: student?.studentIdNumber || rec.studentIdNumber,
        classroomName: classroom?.name || rec.classroomName,
        recordedByName: recordedUser?.fullName || rec.recordedByName,
        createdAt: now,
        updatedAt: now,
      };

      await this.persistAttendanceRecordToPostgres(entry);
      this.attendanceRecords.set(key, entry);
      saved.push(entry);

      if (rec.status === 'PRESENT') present++;
      else if (rec.status === 'ABSENT') absent++;
      else if (rec.status === 'LATE') late++;
      else if (rec.status === 'EXCUSED') excused++;
    }

    // If linked to a session, update session stats
    const activeSessionId = sessionId || records[0]?.sessionId;
    if (activeSessionId) {
      const session = this.getAttendanceSessionById(activeSessionId, organizationId);
      if (session) {
        session.presentCount = present;
        session.absentCount = absent;
        session.lateCount = late;
        session.excusedCount = excused;
        session.totalStudents = records.length;
        session.updatedAt = now;
        await this.persistAttendanceSessionToPostgres(session);
        this.attendanceSessions.set(activeSessionId, session);
      }
    }

    return saved;
  }

  async updateAttendanceRecord(
    id: string,
    organizationId: string,
    updates: Partial<AttendanceRecord>
  ): Promise<AttendanceRecord | undefined> {
    const r = this.getAttendanceRecordById(id, organizationId);
    if (!r) return undefined;

    const updated: AttendanceRecord = {
      ...r,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    await this.persistAttendanceRecordToPostgres(updated);
    this.attendanceRecords.set(id, updated);
    return updated;
  }

  getAttendanceSummaryForStudent(studentId: string, organizationId: string) {
    const records = this.getAttendanceRecords(organizationId, { studentId });
    const totalDays = records.length;
    const presentDays = records.filter((r) => r.status === 'PRESENT').length;
    const absentDays = records.filter((r) => r.status === 'ABSENT').length;
    const lateDays = records.filter((r) => r.status === 'LATE').length;
    const excusedDays = records.filter((r) => r.status === 'EXCUSED').length;
    const attendanceRate =
      totalDays > 0 ? Math.round(((presentDays + lateDays + excusedDays) / totalDays) * 100) : 100;

    return {
      studentId,
      totalDays,
      total: totalDays,
      presentDays,
      present: presentDays,
      absentDays,
      absent: absentDays,
      lateDays,
      late: lateDays,
      excusedDays,
      excused: excusedDays,
      attendanceRate,
      records: records.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()),
    };
  }

  // --- Assessments (Academic Evaluations & Gradebook) ---
  getAssessments(
    organizationId: string,
    filters?: { courseId?: string; classroomId?: string; termId?: string; category?: string; status?: string }
  ): Assessment[] {
    return Array.from(this.assessments.values())
      .filter((a) => {
        if (a.organizationId !== organizationId) return false;
        if (filters?.courseId && a.courseId !== filters.courseId) return false;
        if (filters?.classroomId && a.classroomId !== filters.classroomId) return false;
        if (filters?.termId && a.termId !== filters.termId) return false;
        if (filters?.category && a.category !== filters.category) return false;
        if (filters?.status && a.status !== filters.status) return false;
        return true;
      })
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  getAssessmentById(id: string, organizationId: string): Assessment | undefined {
    const a = this.assessments.get(id);
    if (!a || a.organizationId !== organizationId) return undefined;
    return a;
  }

  async createAssessment(data: Omit<Assessment, 'id' | 'createdAt' | 'updatedAt'>): Promise<Assessment> {
    const id = `ass_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const course = this.getCourseById(data.courseId, data.organizationId);
    const subject = data.subjectId ? this.getSubjectById(data.subjectId, data.organizationId) : course ? this.getSubjectById(course.subjectId, data.organizationId) : undefined;
    const classroom = data.classroomId ? this.getClassroomById(data.classroomId, data.organizationId) : course?.classroomId ? this.getClassroomById(course.classroomId, data.organizationId) : undefined;
    const term = data.termId ? this.getTermById(data.termId, data.organizationId) : course?.termId ? this.getTermById(course.termId, data.organizationId) : undefined;
    const creator = data.createdBy ? this.getUserById(data.createdBy, data.organizationId) : undefined;

    const now = new Date().toISOString();
    const assessment: Assessment = {
      ...data,
      id,
      courseTitle: course?.title,
      subjectId: subject?.id || course?.subjectId,
      subjectName: subject?.name || course?.subjectName,
      classroomId: classroom?.id || course?.classroomId,
      classroomName: classroom?.name || course?.classroomName,
      termId: term?.id || course?.termId,
      termName: term?.name,
      createdByName: creator?.fullName,
      createdAt: now,
      updatedAt: now,
    };
    await this.persistAssessmentToPostgres(assessment);
    this.assessments.set(id, assessment);
    return assessment;
  }

  async updateAssessment(
    id: string,
    organizationId: string,
    updates: Partial<Assessment>
  ): Promise<Assessment | undefined> {
    const a = this.getAssessmentById(id, organizationId);
    if (!a) return undefined;

    const updated: Assessment = {
      ...a,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    await this.persistAssessmentToPostgres(updated);
    this.assessments.set(id, updated);
    return updated;
  }

  async deleteAssessment(id: string, organizationId: string): Promise<boolean> {
    const a = this.getAssessmentById(id, organizationId);
    if (!a) return false;
    await this.deleteAssessmentFromPostgres(id, organizationId);
    this.assessments.delete(id);
    // Delete linked student grades
    for (const [gid, gr] of this.assessmentGrades.entries()) {
      if (gr.organizationId === organizationId && gr.assessmentId === id) {
        await this.deleteAssessmentGradeFromPostgres(gid, organizationId);
        this.assessmentGrades.delete(gid);
      }
    }
    return true;
  }

  // --- Assessment Grades ---
  getAssessmentGrades(
    organizationId: string,
    filters?: { assessmentId?: string; studentId?: string }
  ): AssessmentGrade[] {
    return Array.from(this.assessmentGrades.values()).filter((g) => {
      if (g.organizationId !== organizationId) return false;
      if (filters?.assessmentId && g.assessmentId !== filters.assessmentId) return false;
      if (filters?.studentId && g.studentId !== filters.studentId) return false;
      return true;
    });
  }

  getAssessmentGradeById(id: string, organizationId: string): AssessmentGrade | undefined {
    const g = this.assessmentGrades.get(id);
    if (!g || g.organizationId !== organizationId) return undefined;
    return g;
  }

  async deleteAssessmentGrade(id: string, organizationId: string): Promise<boolean> {
    const g = this.getAssessmentGradeById(id, organizationId);
    if (!g) return false;
    await this.deleteAssessmentGradeFromPostgres(id, organizationId);
    this.assessmentGrades.delete(id);
    return true;
  }

  getAssessmentGradeByStudentAndAssessment(
    assessmentId: string,
    studentId: string,
    organizationId: string
  ): AssessmentGrade | undefined {
    return Array.from(this.assessmentGrades.values()).find(
      (g) => g.organizationId === organizationId && g.assessmentId === assessmentId && g.studentId === studentId
    );
  }

  async recordAssessmentGrade(
    data: Omit<AssessmentGrade, 'id' | 'gradedAt' | 'updatedAt'>
  ): Promise<AssessmentGrade> {
    const assessment = this.getAssessmentById(data.assessmentId, data.organizationId);
    const student = this.getUserById(data.studentId, data.organizationId);
    const grader = data.gradedBy ? this.getUserById(data.gradedBy, data.organizationId) : undefined;
    const maxScore = assessment?.maxScore || data.maxScore || 100;
    const percentage = Number(((data.score / maxScore) * 100).toFixed(2));
    const now = new Date().toISOString();

    const existing = this.getAssessmentGradeByStudentAndAssessment(
      data.assessmentId,
      data.studentId,
      data.organizationId
    );

    if (existing) {
      const updated: AssessmentGrade = {
        ...existing,
        score: data.score,
        percentage,
        feedback: data.feedback !== undefined ? data.feedback : existing.feedback,
        gradedBy: data.gradedBy || existing.gradedBy,
        gradedByName: grader?.fullName || existing.gradedByName,
        updatedAt: now,
      };

      await this.persistAssessmentGradeToPostgres(updated);
      this.assessmentGrades.set(existing.id, updated);
      return updated;
    }

    const id = `grd_${data.assessmentId}_${data.studentId}`;
    const grade: AssessmentGrade = {
      ...data,
      id,
      assessmentTitle: assessment?.title,
      assessmentCategory: assessment?.category,
      maxScore,
      percentage,
      studentName: student?.fullName,
      studentIdNumber: student?.studentIdNumber,
      gradedByName: grader?.fullName,
      gradedAt: now,
      updatedAt: now,
    };

    await this.persistAssessmentGradeToPostgres(grade);
    this.assessmentGrades.set(id, grade);
    return grade;
  }

  async recordAssessmentGradesBatch(
    organizationId: string,
    grades: Omit<AssessmentGrade, 'id' | 'gradedAt' | 'updatedAt'>[]
  ): Promise<AssessmentGrade[]> {
    const recorded: AssessmentGrade[] = [];
    for (const g of grades) {
      recorded.push(await this.recordAssessmentGrade({ ...g, organizationId }));
    }
    return recorded;
  }

  // --- Gradebook Matrix Calculation (Course-Level Holistic Gradebook) ---
  getGradebookMatrix(courseId: string, organizationId: string): (GradebookMatrix & { matrix: any[] }) | undefined {
    const course = this.getCourseById(courseId, organizationId);
    if (!course) return undefined;

    const assessments = this.getAssessments(organizationId, { courseId });
    const assignments = this.getAssignmentsByCourse(courseId, organizationId);

    // Build unified evaluation items
    const evalItems = [
      ...assessments.map((a) => ({
        id: a.id,
        title: a.title,
        category: a.category,
        maxScore: a.maxScore,
        weightPercentage: a.weightPercentage,
        dueDate: a.dueDate,
        isAssignment: false,
      })),
      ...assignments.map((asg) => ({
        id: asg.id,
        title: asg.title,
        category: 'ASSIGNMENT',
        maxScore: asg.maxScore || 100,
        weightPercentage: 0,
        dueDate: asg.dueDate,
        isAssignment: true,
      })),
    ];

    // Find enrolled students for this course / classroom
    let students: User[] = [];
    if (course.classroomId) {
      students = this.getStudentsByClassroom(course.classroomId, organizationId);
    } else {
      // Fallback to students enrolled in the course directly or in org
      students = this.getUsersByOrg(organizationId, 'STUDENT');
    }

    let classTotalEarned = 0;
    let classTotalMax = 0;

    const matrixRows = students.map((student) => {
      const scoresRecord: Record<string, GradebookMatrixStudentScore> = {};
      let studentEarned = 0;
      let studentMax = 0;

      for (const item of evalItems) {
        if (item.isAssignment) {
          const sub = this.getSubmissionsByAssignment(item.id, organizationId).find((s) => s.studentId === student.id);
          if (sub && sub.score !== undefined) {
            const percentage = item.maxScore > 0 ? Number(((sub.score / item.maxScore) * 100).toFixed(2)) : 0;
            scoresRecord[item.id] = {
              score: sub.score,
              maxScore: item.maxScore,
              percentage,
              feedback: sub.teacherFeedback,
              gradedAt: sub.submittedAt,
              status: 'GRADED',
            };
            studentEarned += sub.score;
            studentMax += item.maxScore;
          } else {
            scoresRecord[item.id] = {
              maxScore: item.maxScore,
              status: 'PENDING',
            };
          }
        } else {
          const grade = this.getAssessmentGradeByStudentAndAssessment(item.id, student.id, organizationId);
          if (grade) {
            scoresRecord[item.id] = {
              score: grade.score,
              maxScore: item.maxScore,
              percentage: grade.percentage,
              feedback: grade.feedback,
              gradedAt: grade.gradedAt,
              status: 'GRADED',
            };
            studentEarned += grade.score;
            studentMax += item.maxScore;
          } else {
            scoresRecord[item.id] = {
              maxScore: item.maxScore,
              status: 'PENDING',
            };
          }
        }
      }

      const percentage = studentMax > 0 ? Number(((studentEarned / studentMax) * 100).toFixed(1)) : 0;
      classTotalEarned += studentEarned;
      classTotalMax += studentMax;

      const letterGrade = this.computeLetterGrade(percentage);

      return {
        studentId: student.id,
        studentName: student.fullName,
        studentIdNumber: student.studentIdNumber,
        classroomName: course.classroomName,
        scores: scoresRecord,
        totalEarned: Number(studentEarned.toFixed(1)),
        totalMax: studentMax,
        percentage,
        averagePercent: percentage,
        letterGrade,
      };
    });

    const classAveragePercentage =
      classTotalMax > 0 ? Number(((classTotalEarned / classTotalMax) * 100).toFixed(1)) : 0;

    return {
      course,
      assessments: evalItems.map((a) => ({
        id: a.id,
        title: a.title,
        category: a.category,
        maxScore: a.maxScore,
        weightPercentage: a.weightPercentage,
        dueDate: a.dueDate,
      })),
      students: matrixRows,
      matrix: matrixRows,
      classAveragePercentage,
    };
  }

  // --- Student Academic Performance Summary (Student & Parent Views) ---
  getStudentAcademicPerformance(
    studentId: string,
    organizationId: string
  ): StudentAcademicPerformanceSummary & { breakdown: any[] } {
    const student = this.getUserById(studentId, organizationId);
    const classroomName = student?.classroomId
      ? this.getClassroomById(student.classroomId, organizationId)?.name
      : undefined;

    // Determine enrolled courses
    let courses: Course[] = [];
    if (student?.classroomId) {
      courses = this.getCoursesByClassroom(student.classroomId, organizationId);
    } else {
      courses = this.getCourses(organizationId);
    }

    let overallEarned = 0;
    let overallMax = 0;
    let totalAssessmentsCount = 0;
    let completedAssessmentsCount = 0;
    let pendingAssessmentsCount = 0;

    const coursePerformances = courses.map((c) => {
      const assessments = this.getAssessments(organizationId, { courseId: c.id });
      const assignments = this.getAssignmentsByCourse(c.id, organizationId);
      const evalItems = [
        ...assessments.map((a) => ({
          id: a.id,
          title: a.title,
          category: a.category,
          maxScore: a.maxScore,
          weightPercentage: a.weightPercentage,
          dueDate: a.dueDate,
          isAssignment: false,
        })),
        ...assignments.map((asg) => ({
          id: asg.id,
          title: asg.title,
          category: 'ASSIGNMENT',
          maxScore: asg.maxScore || 100,
          weightPercentage: 0,
          dueDate: asg.dueDate,
          isAssignment: true,
        })),
      ];

      let cEarned = 0;
      let cMax = 0;
      let cGradedCount = 0;
      let cPendingCount = 0;

      const items: StudentAssessmentItem[] = evalItems.map((evalItem) => {
        totalAssessmentsCount++;
        let isGraded = false;
        let score: number | undefined;
        let feedback: string | undefined;
        let gradedAt: string | undefined;

        if (evalItem.isAssignment) {
          const sub = this.getSubmissionsByAssignment(evalItem.id, organizationId).find((s) => s.studentId === studentId);
          if (sub && sub.score !== undefined) {
            isGraded = true;
            score = sub.score;
            feedback = sub.teacherFeedback;
            gradedAt = sub.submittedAt;
          }
        } else {
          const grade = this.getAssessmentGradeByStudentAndAssessment(evalItem.id, studentId, organizationId);
          if (grade) {
            isGraded = true;
            score = grade.score;
            feedback = grade.feedback;
            gradedAt = grade.gradedAt;
          }
        }

        if (isGraded && score !== undefined) {
          completedAssessmentsCount++;
          cGradedCount++;
          cEarned += score;
          cMax += evalItem.maxScore;
          const percentage = evalItem.maxScore > 0 ? Number(((score / evalItem.maxScore) * 100).toFixed(2)) : 0;
          return {
            assessmentId: evalItem.id,
            title: evalItem.title,
            category: evalItem.category,
            maxScore: evalItem.maxScore,
            weightPercentage: evalItem.weightPercentage,
            score,
            percentage,
            feedback,
            gradedAt,
            dueDate: evalItem.dueDate,
            status: 'GRADED',
          };
        } else {
          pendingAssessmentsCount++;
          cPendingCount++;
          const isOverdue = evalItem.dueDate && new Date(evalItem.dueDate).getTime() < Date.now();
          return {
            assessmentId: evalItem.id,
            title: evalItem.title,
            category: evalItem.category,
            maxScore: evalItem.maxScore,
            weightPercentage: evalItem.weightPercentage,
            dueDate: evalItem.dueDate,
            status: isOverdue ? 'MISSED' : 'PENDING',
          };
        }
      });

      overallEarned += cEarned;
      overallMax += cMax;

      const cPercent = cMax > 0 ? Number(((cEarned / cMax) * 100).toFixed(1)) : 0;
      const letterGrade = this.computeLetterGrade(cPercent);

      return {
        courseId: c.id,
        courseTitle: c.title,
        subjectId: c.subjectId,
        subjectName: c.subjectName,
        teacherName: c.teacherName,
        classroomName: c.classroomName,
        totalAssessments: evalItems.length,
        gradedAssessments: cGradedCount,
        pendingAssessments: cPendingCount,
        earnedPoints: Number(cEarned.toFixed(1)),
        earned: Number(cEarned.toFixed(1)),
        maxPossiblePoints: cMax,
        max: cMax,
        percentage: cPercent,
        average: cPercent,
        letterGrade,
        assessments: items,
      };
    });

    const overallGpaPercent =
      overallMax > 0 ? Number(((overallEarned / overallMax) * 100).toFixed(1)) : 0;
    const letterGrade = this.computeLetterGrade(overallGpaPercent);

    return {
      studentId,
      studentName: student?.fullName || 'الطالب',
      studentIdNumber: student?.studentIdNumber,
      classroomName,
      enrolledCoursesCount: courses.length,
      totalAssessmentsCount,
      completedAssessmentsCount,
      pendingAssessmentsCount,
      overallGpaPercent,
      letterGrade,
      courses: coursePerformances,
      breakdown: coursePerformances,
    };
  }

  computeLetterGrade(percentage: number): string {
    if (percentage >= 95) return 'A+';
    if (percentage >= 90) return 'A';
    if (percentage >= 85) return 'B+';
    if (percentage >= 80) return 'B';
    if (percentage >= 75) return 'C+';
    if (percentage >= 70) return 'C';
    if (percentage >= 60) return 'D';
    if (percentage > 0) return 'F';
    return 'N/A';
  }

  // Audit Logging
  logAction(organizationId: string, userId: string | undefined, userEmail: string | undefined, action: string, resourceType: string, resourceId: string, details?: Record<string, unknown>, ipAddress?: string): AuditLog {
    const id = `log_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const log: AuditLog = {
      id,
      organizationId,
      userId,
      userEmail,
      action,
      resourceType,
      resourceId,
      details,
      ipAddress,
      timestamp: new Date().toISOString(),
    };
    this.auditLogs.set(id, log);
    return log;
  }

  getAuditLogs(organizationId: string, limit = 50): AuditLog[] {
    return Array.from(this.auditLogs.values())
      .filter((l) => l.organizationId === organizationId)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }

  // --- Invitations Management ---
  createInvitation(data: Omit<Invitation, 'id' | 'createdAt' | 'isUsed'>): Invitation {
    const id = `inv_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const classroom = data.classroomId ? this.classrooms.get(data.classroomId) : undefined;
    const creator = data.createdBy ? this.users.get(data.createdBy) : undefined;

    const inv: Invitation = {
      id,
      ...data,
      classroomName: classroom?.name,
      createdByName: creator?.fullName,
      isUsed: false,
      createdAt: new Date().toISOString(),
    };
    this.invitations.set(id, inv);
    return inv;
  }

  getInvitationByCode(code: string): Invitation | undefined {
    const normalized = code.trim().toUpperCase();
    for (const inv of this.invitations.values()) {
      if (inv.inviteCode.toUpperCase() === normalized) {
        return inv;
      }
    }
    return undefined;
  }

  getPendingInvitationsByEmail(email: string): Invitation[] {
    const normalized = email.toLowerCase().trim();
    const now = Date.now();
    return Array.from(this.invitations.values())
      .filter((inv) => inv.email.toLowerCase().trim() === normalized && !inv.isUsed && new Date(inv.expiresAt).getTime() > now)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  getInvitationsByOrg(organizationId: string): Invitation[] {
    return Array.from(this.invitations.values())
      .filter((inv) => inv.organizationId === organizationId)
      .map((inv) => {
        const classroom = inv.classroomId ? this.classrooms.get(inv.classroomId) : undefined;
        const creator = inv.createdBy ? this.users.get(inv.createdBy) : undefined;
        return {
          ...inv,
          classroomName: classroom?.name || inv.classroomName,
          createdByName: creator?.fullName || inv.createdByName,
        };
      })
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  revokeInvitation(id: string, organizationId: string): boolean {
    const inv = this.invitations.get(id);
    if (!inv || inv.organizationId !== organizationId) return false;
    return this.invitations.delete(id);
  }

  markInvitationUsed(id: string, organizationId: string): boolean {
    const inv = this.invitations.get(id);
    if (!inv || inv.organizationId !== organizationId) return false;
    inv.isUsed = true;
    inv.usedAt = new Date().toISOString();
    this.invitations.set(id, inv);
    return true;
  }

  private mapInvitationRow(row: any): Invitation {
    return {
      id: row.id,
      organizationId: row.organization_id,
      email: row.email,
      role: row.role,
      inviteCode: row.invite_code,
      tokenHash: row.token_hash || undefined,
      fullName: row.full_name || undefined,
      classroomId: row.classroom_id || undefined,
      classroomName: row.classroom_name || undefined,
      teacherSpecialization: row.teacher_specialization || undefined,
      studentIdNumber: row.student_id_number || undefined,
      createdBy: row.created_by || undefined,
      createdByName: row.created_by_name || undefined,
      expiresAt: row.expires_at?.toISOString ? row.expires_at.toISOString() : String(row.expires_at),
      usedAt: row.used_at?.toISOString ? row.used_at.toISOString() : (row.used_at || undefined),
      isUsed: Boolean(row.is_used),
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
    };
  }

  private invitationSelectSql() {
    return `
      SELECT i.id, i.organization_id, i.email, i.role, i.invite_code, i."tokenHash" AS token_hash,
             i.full_name, i.classroom_id, c.name AS classroom_name, i.teacher_specialization,
             i.student_id_number, i.created_by, creator.full_name AS created_by_name,
             i.expires_at, i.used_at, i.is_used, i.created_at
      FROM invitations i
      LEFT JOIN classrooms c ON c.id = i.classroom_id AND c.organization_id = i.organization_id
      LEFT JOIN users creator ON creator.id = i.created_by AND creator.organization_id = i.organization_id`;
  }

  async createInvitationAsync(data: Omit<Invitation, 'id' | 'createdAt' | 'isUsed'>): Promise<Invitation> {
    if (process.env.NODE_ENV !== 'production') return this.createInvitation(data);
    const id = generateId('inv');
    return this.withIdentityTenant(data.organizationId, async (client) => {
      const result = await client.query(
        `INSERT INTO invitations (
           id, organization_id, email, role, invite_code, "tokenHash", full_name,
           classroom_id, teacher_specialization, student_id_number, created_by,
           expires_at, is_used, created_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, FALSE, CURRENT_TIMESTAMP)
         RETURNING id, organization_id, email, role, invite_code, "tokenHash", full_name,
                   classroom_id, teacher_specialization, student_id_number, created_by,
                   expires_at, used_at, is_used, created_at`,
        [id, data.organizationId, data.email.trim().toLowerCase(), data.role, data.inviteCode.toUpperCase(), data.tokenHash || null, data.fullName || null, data.classroomId || null, data.teacherSpecialization || null, data.studentIdNumber || null, data.createdBy || null, data.expiresAt]
      );
      const invitation = this.mapInvitationRow(result.rows[0]);
      const classroom = data.classroomId ? await client.query('SELECT name FROM classrooms WHERE id = $1 AND organization_id = $2', [data.classroomId, data.organizationId]) : undefined;
      invitation.classroomName = classroom?.rows[0]?.name;
      return invitation;
    });
  }

  async getInvitationByCodeAsync(code: string): Promise<Invitation | undefined> {
    if (process.env.NODE_ENV !== 'production') return this.getInvitationByCode(code);
    const normalized = code.trim().toUpperCase();
    for (const organizationId of await this.getProductionOrganizationIds()) {
      const invitation = await this.withIdentityTenant(organizationId, async (client) => {
        const result = await client.query(
          `${this.invitationSelectSql()} WHERE i.organization_id = $1 AND upper(i.invite_code) = $2`,
          [organizationId, normalized]
        );
        return result.rows[0] ? this.mapInvitationRow(result.rows[0]) : undefined;
      });
      if (invitation) return invitation;
    }
    return undefined;
  }

  async getPendingInvitationsByEmailAsync(email: string): Promise<Invitation[]> {
    if (process.env.NODE_ENV !== 'production') return this.getPendingInvitationsByEmail(email);
    const pending: Invitation[] = [];
    for (const organizationId of await this.getProductionOrganizationIds()) {
      const rows = await this.withIdentityTenant(organizationId, async (client) => {
        const result = await client.query(
          `${this.invitationSelectSql()}
           WHERE i.organization_id = $1 AND lower(i.email) = $2 AND i.is_used = FALSE AND i.used_at IS NULL
             AND i.expires_at > CURRENT_TIMESTAMP
           ORDER BY i.created_at DESC`,
          [organizationId, email.trim().toLowerCase()]
        );
        return result.rows;
      });
      pending.push(...rows.map((row: any) => this.mapInvitationRow(row)));
    }
    return pending.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  async getInvitationsByOrgAsync(organizationId: string): Promise<Invitation[]> {
    if (process.env.NODE_ENV !== 'production') return this.getInvitationsByOrg(organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `${this.invitationSelectSql()} WHERE i.organization_id = $1 ORDER BY i.created_at DESC`,
        [organizationId]
      );
      return result.rows.map((row: any) => this.mapInvitationRow(row));
    });
  }

  async revokeInvitationAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.revokeInvitation(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `UPDATE invitations SET is_used = TRUE, used_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND organization_id = $2 AND is_used = FALSE AND used_at IS NULL
           AND expires_at > CURRENT_TIMESTAMP
         RETURNING id`,
        [id, organizationId]
      );
      return result.rowCount === 1;
    });
  }

  async markInvitationUsedAsync(id: string, organizationId: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') return this.markInvitationUsed(id, organizationId);
    return this.withIdentityTenant(organizationId, async (client) => {
      const result = await client.query(
        `UPDATE invitations SET is_used = TRUE, used_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND organization_id = $2 AND is_used = FALSE AND used_at IS NULL
           AND expires_at > CURRENT_TIMESTAMP
         RETURNING id`,
        [id, organizationId]
      );
      return result.rowCount === 1;
    });
  }


  // ==========================================
  // Rtiqa AI Engine Database Methods (Multi-Tenant)
  // ==========================================

  // --- AI Conversations ---
  getAIConversations(organizationId: string, userId?: string): AIConversation[] {
    return Array.from(this.aiConversations.values())
      .filter((c) => c.organizationId === organizationId && (!userId || c.userId === userId))
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
  }

  getAIConversationById(id: string, organizationId: string, userId?: string): AIConversation | null {
    const conv = this.aiConversations.get(id);
    if (!conv || conv.organizationId !== organizationId) return null;
    if (userId && conv.userId !== userId) return null;
    return conv;
  }

  createAIConversation(conv: AIConversation): AIConversation {
    this.aiConversations.set(conv.id, conv);
    return conv;
  }

  updateAIConversation(id: string, organizationId: string, updates: Partial<AIConversation>): AIConversation | null {
    const conv = this.getAIConversationById(id, organizationId);
    if (!conv) return null;
    const updated = {
      ...conv,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.aiConversations.set(id, updated);
    return updated;
  }

  deleteAIConversation(id: string, organizationId: string, userId?: string): boolean {
    const conv = this.getAIConversationById(id, organizationId, userId);
    if (!conv) return false;
    this.aiConversations.delete(id);
    // Cascade delete conversation messages
    for (const [msgId, msg] of this.aiMessages.entries()) {
      if (msg.conversationId === id) {
        this.aiMessages.delete(msgId);
      }
    }
    return true;
  }

  // --- AI Messages ---
  getAIMessages(conversationId: string, organizationId: string): AIMessage[] {
    // Validate conversation belongs to organization first
    const conv = this.getAIConversationById(conversationId, organizationId);
    if (!conv) return [];

    return Array.from(this.aiMessages.values())
      .filter((m) => m.conversationId === conversationId && m.organizationId === organizationId)
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  }

  createAIMessage(msg: AIMessage): AIMessage {
    this.aiMessages.set(msg.id, msg);
    // Touch conversation updated_at
    const conv = this.aiConversations.get(msg.conversationId);
    if (conv) {
      conv.updatedAt = new Date().toISOString();
      this.aiConversations.set(conv.id, conv);
    }
    return msg;
  }

  // --- AI Usage & Quotas ---
  recordAIUsage(usage: AIUsageRecord): AIUsageRecord {
    this.aiUsageRecords.set(usage.id, usage);
    return usage;
  }

  getAIUsage(organizationId: string, userId?: string): AIUsageRecord[] {
    return Array.from(this.aiUsageRecords.values())
      .filter((u) => u.organizationId === organizationId && (!userId || u.userId === userId))
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  getAIUsageSummary(organizationId: string): AIUsageSummary {
    const records = this.getAIUsage(organizationId);
    const monthlyQuotaTokens = 1000000; // 1M tokens monthly default quota per school
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let totalCostUsd = 0;
    const featureBreakdown: Record<string, { requests: number; tokens: number; cost: number }> = {};

    for (const r of records) {
      totalInputTokens += r.inputTokens || 0;
      totalOutputTokens += r.outputTokens || 0;
      totalCostUsd += Number(r.estimatedCost) || 0;

      const feat = r.featureName || 'other';
      if (!featureBreakdown[feat]) {
        featureBreakdown[feat] = { requests: 0, tokens: 0, cost: 0 };
      }
      featureBreakdown[feat].requests += 1;
      featureBreakdown[feat].tokens += (r.inputTokens || 0) + (r.outputTokens || 0);
      featureBreakdown[feat].cost += Number(r.estimatedCost) || 0;
    }

    const totalTokens = totalInputTokens + totalOutputTokens;
    const usedQuotaPercentage = Math.min(100, Math.round((totalTokens / monthlyQuotaTokens) * 100));

    return {
      organizationId,
      totalTokens,
      totalInputTokens,
      totalOutputTokens,
      totalCostUsd: Number(totalCostUsd.toFixed(6)),
      monthlyQuotaTokens,
      usedQuotaPercentage,
      requestsCount: records.length,
      featureBreakdown,
    };
  }

  // --- AI Document Chunks (RAG Foundation) ---
  createAIDocumentChunk(chunk: AIDocumentChunk): AIDocumentChunk {
    this.aiDocumentChunks.set(chunk.id, chunk);
    return chunk;
  }

  deleteAIDocumentChunksBySource(organizationId: string, sourceId: string): void {
    for (const [id, chunk] of this.aiDocumentChunks.entries()) {
      if (chunk.organizationId === organizationId && chunk.sourceId === sourceId) {
        this.aiDocumentChunks.delete(id);
      }
    }
  }

  getAIDocumentChunks(organizationId: string, documentId?: string): AIDocumentChunk[] {
    return Array.from(this.aiDocumentChunks.values())
      .filter((c) => c.organizationId === organizationId && (!documentId || c.documentId === documentId))
      .sort((a, b) => a.chunkIndex - b.chunkIndex);
  }

  // ==========================================
  // Object Storage Metadata Methods (Multi-Tenant)
  // ==========================================

  async createStorageObject(
    data: Omit<StorageObjectMetadata, 'createdAt' | 'updatedAt'> & { createdAt?: string; updatedAt?: string }
  ): Promise<StorageObjectMetadata> {
    const now = new Date().toISOString();
    const obj: StorageObjectMetadata = {
      ...data,
      id: data.id || `obj_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      createdAt: data.createdAt || now,
      updatedAt: data.updatedAt || now,
    };

    await this.persistStorageObjectToPostgres(obj);
    this.storageObjects.set(obj.id, obj);
    return obj;
  }

  getStorageObjectById(id: string, organizationId: string): StorageObjectMetadata | undefined {
    const obj = this.storageObjects.get(id);
    if (!obj || obj.organizationId !== organizationId) return undefined;
    return obj;
  }

  getStorageObjectsByResource(
    resourceType: StorageResourceType,
    resourceId: string,
    organizationId: string
  ): StorageObjectMetadata[] {
    return Array.from(this.storageObjects.values())
      .filter(
        (o) =>
          o.organizationId === organizationId &&
          o.resourceType === resourceType &&
          o.resourceId === resourceId &&
          o.status !== 'DELETED'
      )
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  getStorageObjectsByOrg(organizationId: string): StorageObjectMetadata[] {
    return Array.from(this.storageObjects.values())
      .filter((o) => o.organizationId === organizationId && o.status !== 'DELETED')
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  async updateStorageObject(
    id: string,
    organizationId: string,
    updates: Partial<StorageObjectMetadata>
  ): Promise<StorageObjectMetadata | undefined> {
    const obj = this.getStorageObjectById(id, organizationId);
    if (!obj) return undefined;

    const updated: StorageObjectMetadata = {
      ...obj,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    await this.persistStorageObjectToPostgres(updated);
    this.storageObjects.set(id, updated);
    return updated;
  }

  async deleteStorageObject(id: string, organizationId: string, hardDelete = false): Promise<boolean> {
    const obj = this.getStorageObjectById(id, organizationId);
    if (!obj) return false;

    if (hardDelete) {
      await this.deleteStorageObjectFromPostgres(id, organizationId, true);
      this.storageObjects.delete(id);
    } else {
      const now = new Date().toISOString();
      const updated: StorageObjectMetadata = {
        ...obj,
        status: 'DELETED',
        deletedAt: now,
        updatedAt: now,
      };
      await this.persistStorageObjectToPostgres(updated);
      this.storageObjects.set(id, updated);
    }
    return true;
  }

  private async persistStorageObjectToPostgres(obj: StorageObjectMetadata): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    try {
      await pool.query(
      `INSERT INTO storage_objects (
        id, organization_id, object_key, original_filename, content_type, size_bytes,
        checksum, resource_type, resource_id, uploaded_by, status, metadata,
        created_at, updated_at, deleted_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      ON CONFLICT (id) DO UPDATE SET
        object_key = EXCLUDED.object_key,
        original_filename = EXCLUDED.original_filename,
        content_type = EXCLUDED.content_type,
        size_bytes = EXCLUDED.size_bytes,
        checksum = EXCLUDED.checksum,
        resource_type = EXCLUDED.resource_type,
        resource_id = EXCLUDED.resource_id,
        status = EXCLUDED.status,
        metadata = EXCLUDED.metadata,
        updated_at = EXCLUDED.updated_at,
        deleted_at = EXCLUDED.deleted_at;`,
      [
        obj.id,
        obj.organizationId,
        obj.objectKey,
        obj.originalFilename,
        obj.contentType,
        obj.sizeBytes,
        obj.checksum || null,
        obj.resourceType,
        obj.resourceId,
        obj.uploadedBy,
        obj.status,
        JSON.stringify(obj.metadata || {}),
        obj.createdAt,
        obj.updatedAt,
        obj.deletedAt || null,
      ]
      );
    } catch (err: any) {
      if (process.env.NODE_ENV === 'production') {
        console.error('[PostgreSQL Critical Error]: Failed to persist storage object', err);
        throw err;
      }
      console.error('[PostgreSQL Storage Object Persist Warning]:', err.message);
    }
  }

  private async deleteStorageObjectFromPostgres(id: string, organizationId: string, hardDelete = false): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('PostgreSQL is required in production environment.');
      }
      return;
    }
    if (hardDelete) {
      try {
        await pool.query('DELETE FROM storage_objects WHERE id = $1 AND organization_id = $2', [id, organizationId]);
      } catch (err: any) {
        if (process.env.NODE_ENV === 'production') throw err;
        console.error('[PostgreSQL Delete Storage Object Warning]:', err.message);
      }
    } else {
      try {
        await pool.query(
        "UPDATE storage_objects SET status = 'DELETED', deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND organization_id = $2",
        [id, organizationId]
        );
      } catch (err: any) {
        if (process.env.NODE_ENV === 'production') throw err;
        console.error('[PostgreSQL Soft Delete Storage Object Warning]:', err.message);
      }
    }
  }

  async syncStorageObjectsFromPostgres(organizationId?: string): Promise<void> {
    const pool = getPostgresPool();
    if (!pool) return;

    try {
      let query = 'SELECT * FROM storage_objects';
      const params: any[] = [];
      if (organizationId) {
        query += ' WHERE organization_id = $1';
        params.push(organizationId);
      }
      const res = await pool.query(query, params);
      for (const row of res.rows) {
        const obj: StorageObjectMetadata = {
          id: row.id,
          organizationId: row.organization_id,
          objectKey: row.object_key,
          originalFilename: row.original_filename,
          contentType: row.content_type,
          sizeBytes: Number(row.size_bytes) || 0,
          checksum: row.checksum || undefined,
          resourceType: row.resource_type as StorageResourceType,
          resourceId: row.resource_id,
          uploadedBy: row.uploaded_by,
          status: row.status as StorageObjectStatus,
          metadata: row.metadata || {},
          createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : (row.created_at || new Date().toISOString()),
          updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : (row.updated_at || new Date().toISOString()),
          deletedAt: row.deleted_at?.toISOString ? row.deleted_at.toISOString() : (row.deleted_at || undefined),
        };
        this.storageObjects.set(obj.id, obj);
      }
    } catch (err) {
      if (process.env.NODE_ENV === 'production') throw err;
      console.error('[PostgreSQL Storage Sync Warning]:', (err as Error).message);
    }
  }

  // Reset database state (useful for automated tests)
  resetData(): void {
    const isTestProcess = process.argv.some((arg) => arg.includes('--test') || arg.includes('/test/'));
    if (process.env.NODE_ENV === 'production' && !isTestProcess) {
      throw new Error('RESET_DATA_DISABLED_IN_PRODUCTION');
    }

    this.organizations.clear();
    this.users.clear();
    this.academicYears.clear();
    this.terms.clear();
    this.gradeLevels.clear();
    this.classrooms.clear();
    this.subjects.clear();
    this.courses.clear();
    this.lessons.clear();
    this.assignments.clear();
    this.submissions.clear();
    this.attendanceSessions.clear();
    this.attendanceRecords.clear();
    this.assessments.clear();
    this.assessmentGrades.clear();
    this.storageObjects.clear();
    this.auditLogs.clear();
    this.invitations.clear();
    this.organizationMemberships.clear();
    this.passwordResetTokens.clear();
    this.emailVerificationTokens.clear();
    this.phoneVerificationOtps.clear();
    this.aiConversations.clear();
    this.aiMessages.clear();
    this.aiUsageRecords.clear();
    this.aiDocumentChunks.clear();
    this.teacherAssignments.clear();
    this.studentEnrollments.clear();
    this.parentStudentLinks.clear();
    this.studentRecords.clear();
    this.studentBehaviorRecords.clear();
    this.studentLifecycleEvents.clear();
    this.notifications.clear();
    this.seedInitialData();
  }

  // ==========================================
  // Notification Management Operations
  // ==========================================

  createNotification(data: Omit<NotificationItem, 'id' | 'createdAt' | 'isRead'>): NotificationItem {
    const id = `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const notification: NotificationItem = {
      id,
      organizationId: data.organizationId,
      recipientId: data.recipientId,
      recipientRole: data.recipientRole,
      type: data.type,
      title: data.title,
      body: data.body,
      data: data.data || {},
      channels: data.channels || ['IN_APP'],
      isRead: false,
      createdAt: new Date().toISOString(),
    };

    this.notifications.set(id, notification);
    return notification;
  }

  getNotifications(
    orgId: string,
    recipientId: string,
    filter?: { unreadOnly?: boolean; limit?: number }
  ): NotificationItem[] {
    let items = Array.from(this.notifications.values()).filter(
      (n) => n.organizationId === orgId && n.recipientId === recipientId
    );

    if (filter?.unreadOnly) {
      items = items.filter((n) => !n.isRead);
    }

    // Sort newest first
    items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    if (filter?.limit) {
      items = items.slice(0, filter.limit);
    }

    return items;
  }

  markNotificationAsRead(id: string, orgId: string, recipientId: string): boolean {
    const notif = this.notifications.get(id);
    if (!notif || notif.organizationId !== orgId || notif.recipientId !== recipientId) {
      return false;
    }

    notif.isRead = true;
    notif.readAt = new Date().toISOString();
    this.notifications.set(id, notif);
    return true;
  }

  markAllNotificationsAsRead(orgId: string, recipientId: string): number {
    let count = 0;
    const now = new Date().toISOString();

    for (const [id, notif] of this.notifications.entries()) {
      if (notif.organizationId === orgId && notif.recipientId === recipientId && !notif.isRead) {
        notif.isRead = true;
        notif.readAt = now;
        this.notifications.set(id, notif);
        count++;
      }
    }

    return count;
  }

  getUnreadNotificationCount(orgId: string, recipientId: string): number {
    let count = 0;
    for (const notif of this.notifications.values()) {
      if (notif.organizationId === orgId && notif.recipientId === recipientId && !notif.isRead) {
        count++;
      }
    }
    return count;
  }

  // Verification helpers
  isSubjectInOrg(subjectId: string, orgId: string): boolean {
    const s = this.subjects.get(subjectId);
    return Boolean(s && s.organizationId === orgId);
  }

  isTermInOrg(termId: string, orgId: string): boolean {
    const t = this.terms.get(termId);
    return Boolean(t && t.organizationId === orgId);
  }

  isClassroomInOrg(classroomId: string, orgId: string): boolean {
    const c = this.classrooms.get(classroomId);
    return Boolean(c && c.organizationId === orgId);
  }

  isGradeLevelInOrg(gradeId: string, orgId: string): boolean {
    const g = this.gradeLevels.get(gradeId);
    return Boolean(g && g.organizationId === orgId);
  }

  isAcademicYearInOrg(yearId: string, orgId: string): boolean {
    const y = this.academicYears.get(yearId);
    return Boolean(y && y.organizationId === orgId);
  }

  // ==========================================
  // Phase 5.1: Curriculum Units Management
  // ==========================================

  getUnitsByCourse(courseId: string, orgId: string): CurriculumUnit[] {
    const course = this.courses.get(courseId);
    if (!course || course.organizationId !== orgId) return [];

    return Array.from(this.curriculumUnits.values())
      .filter((u) => u.organizationId === orgId && u.courseId === courseId)
      .map((u) => ({
        ...u,
        courseTitle: course.title,
      }))
      .sort((a, b) => a.orderIndex - b.orderIndex);
  }

  getUnitById(unitId: string, orgId: string): CurriculumUnit | undefined {
    const unit = this.curriculumUnits.get(unitId);
    if (!unit || unit.organizationId !== orgId) return undefined;
    const course = this.courses.get(unit.courseId);
    return {
      ...unit,
      courseTitle: course?.title,
    };
  }

  createUnit(data: Omit<CurriculumUnit, 'id' | 'createdAt' | 'updatedAt'>): CurriculumUnit {
    const id = generateId('unit');
    const now = new Date().toISOString();
    const course = this.courses.get(data.courseId);
    const unit: CurriculumUnit = {
      ...data,
      id,
      courseTitle: course?.title,
      createdAt: now,
      updatedAt: now,
    };
    this.curriculumUnits.set(id, unit);
    return unit;
  }

  updateUnit(id: string, orgId: string, updates: Partial<CurriculumUnit>): CurriculumUnit | undefined {
    const unit = this.getUnitById(id, orgId);
    if (!unit) return undefined;
    const updated: CurriculumUnit = {
      ...unit,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.curriculumUnits.set(id, updated);
    return updated;
  }

  deleteUnit(id: string, orgId: string): boolean {
    const unit = this.getUnitById(id, orgId);
    if (!unit) return false;
    this.curriculumUnits.delete(id);
    return true;
  }

  // ==========================================
  // Phase 5.1: Digital Learning Library Resources
  // ==========================================

  getLibraryResources(
    orgId: string,
    filter?: {
      subjectId?: string;
      gradeLevelId?: string;
      courseId?: string;
      unitId?: string;
      lessonId?: string;
      resourceType?: LibraryResourceType;
      status?: LibraryResourceStatus;
      visibility?: LibraryResourceVisibility;
      search?: string;
      role?: string;
      userId?: string;
      enrolledCourseIds?: string[];
    }
  ): LibraryResource[] {
    let resources = Array.from(this.libraryResources.values()).filter((r) => r.organizationId === orgId);

    // Role-based visibility filtering
    if (filter?.role) {
      if (filter.role === 'STUDENT') {
        resources = resources.filter((r) => {
          if (r.status !== 'PUBLISHED') return false;
          if (r.visibility === 'PUBLIC_SCHOOL') return true;
          if (r.visibility === 'COURSE_STUDENTS') {
            if (!r.courseId) return true;
            return filter.enrolledCourseIds?.includes(r.courseId) ?? false;
          }
          return false;
        });
      } else if (filter.role === 'PARENT') {
        resources = resources.filter((r) => {
          if (r.status !== 'PUBLISHED') return false;
          return r.visibility === 'PUBLIC_SCHOOL' || r.visibility === 'COURSE_STUDENTS';
        });
      } else if (filter.role === 'TEACHER') {
        resources = resources.filter((r) => {
          if (r.visibility === 'PRIVATE' && r.uploadedBy !== filter.userId) return false;
          return true;
        });
      }
    }

    if (filter?.subjectId) {
      resources = resources.filter((r) => r.subjectId === filter.subjectId);
    }
    if (filter?.gradeLevelId) {
      resources = resources.filter((r) => r.gradeLevelId === filter.gradeLevelId);
    }
    if (filter?.courseId) {
      resources = resources.filter((r) => r.courseId === filter.courseId);
    }
    if (filter?.unitId) {
      resources = resources.filter((r) => r.unitId === filter.unitId);
    }
    if (filter?.lessonId) {
      resources = resources.filter((r) => r.lessonId === filter.lessonId);
    }
    if (filter?.resourceType) {
      resources = resources.filter((r) => r.resourceType === filter.resourceType);
    }
    if (filter?.status) {
      resources = resources.filter((r) => r.status === filter.status);
    }
    if (filter?.visibility) {
      resources = resources.filter((r) => r.visibility === filter.visibility);
    }
    if (filter?.search && filter.search.trim()) {
      const q = filter.search.trim().toLowerCase();
      resources = resources.filter(
        (r) =>
          r.title.toLowerCase().includes(q) ||
          (r.description && r.description.toLowerCase().includes(q)) ||
          (Array.isArray(r.tags) && r.tags.some((t) => t.toLowerCase().includes(q))) ||
          (r.authorName && r.authorName.toLowerCase().includes(q))
      );
    }

    return resources.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  getLibraryResourceById(id: string, orgId: string): LibraryResource | undefined {
    const res = this.libraryResources.get(id);
    if (!res || res.organizationId !== orgId) return undefined;
    return res;
  }

  createLibraryResource(
    data: Omit<LibraryResource, 'id' | 'viewCount' | 'downloadCount' | 'completionCount' | 'createdAt' | 'updatedAt' | 'tags' | 'aiSearchable'> & {
      tags?: string[];
      aiSearchable?: boolean;
    }
  ): LibraryResource {
    const id = `res_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();

    const subject = data.subjectId ? this.subjects.get(data.subjectId) : undefined;
    const gradeLevel = data.gradeLevelId ? this.gradeLevels.get(data.gradeLevelId) : undefined;
    const course = data.courseId ? this.courses.get(data.courseId) : undefined;
    const unit = data.unitId ? this.curriculumUnits.get(data.unitId) : undefined;
    const lesson = data.lessonId ? this.lessons.get(data.lessonId) : undefined;
    const uploader = this.users.get(data.uploadedBy);

    const resource: LibraryResource = {
      ...data,
      id,
      tags: Array.isArray(data.tags) ? data.tags : [],
      aiSearchable: data.aiSearchable !== false,
      subjectName: subject?.name,
      gradeLevelName: gradeLevel?.name,
      courseTitle: course?.title,
      unitTitle: unit?.title,
      lessonTitle: lesson?.title,
      authorName: uploader?.fullName || data.authorName || 'معلم',
      viewCount: 0,
      downloadCount: 0,
      completionCount: 0,
      createdAt: now,
      updatedAt: now,
    };

    this.libraryResources.set(id, resource);
    return resource;
  }

  updateLibraryResource(id: string, orgId: string, updates: Partial<LibraryResource>): LibraryResource | undefined {
    const res = this.getLibraryResourceById(id, orgId);
    if (!res) return undefined;

    const subject = updates.subjectId ? this.subjects.get(updates.subjectId) : res.subjectId ? this.subjects.get(res.subjectId) : undefined;
    const gradeLevel = updates.gradeLevelId ? this.gradeLevels.get(updates.gradeLevelId) : res.gradeLevelId ? this.gradeLevels.get(res.gradeLevelId) : undefined;
    const course = updates.courseId ? this.courses.get(updates.courseId) : res.courseId ? this.courses.get(res.courseId) : undefined;
    const unit = updates.unitId ? this.curriculumUnits.get(updates.unitId) : res.unitId ? this.curriculumUnits.get(res.unitId) : undefined;
    const lesson = updates.lessonId ? this.lessons.get(updates.lessonId) : res.lessonId ? this.lessons.get(res.lessonId) : undefined;

    const updated: LibraryResource = {
      ...res,
      ...updates,
      subjectName: subject?.name || res.subjectName,
      gradeLevelName: gradeLevel?.name || res.gradeLevelName,
      courseTitle: course?.title || res.courseTitle,
      unitTitle: unit?.title || res.unitTitle,
      lessonTitle: lesson?.title || res.lessonTitle,
      updatedAt: new Date().toISOString(),
    };

    this.libraryResources.set(id, updated);
    return updated;
  }

  deleteLibraryResource(id: string, orgId: string): boolean {
    const res = this.getLibraryResourceById(id, orgId);
    if (!res) return false;
    this.libraryResources.delete(id);
    return true;
  }

  recordResourceActivity(data: Omit<ResourceActivity, 'id' | 'timestamp'>): ResourceActivity {
    const id = `act_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();
    const user = this.users.get(data.userId);

    const activity: ResourceActivity = {
      ...data,
      id,
      userName: user?.fullName,
      timestamp: now,
    };
    this.resourceActivities.set(id, activity);

    // Increment resource stats
    const res = this.libraryResources.get(data.resourceId);
    if (res && res.organizationId === data.organizationId) {
      if (data.action === 'VIEWED') res.viewCount = (res.viewCount || 0) + 1;
      if (data.action === 'DOWNLOADED') res.downloadCount = (res.downloadCount || 0) + 1;
      if (data.action === 'COMPLETED') res.completionCount = (res.completionCount || 0) + 1;
      this.libraryResources.set(res.id, res);
    }

    return activity;
  }

  getLibraryStats(orgId: string): LibraryStats {
    const resources = Array.from(this.libraryResources.values()).filter((r) => r.organizationId === orgId);
    
    let totalViews = 0;
    let totalDownloads = 0;
    let totalCompletions = 0;

    const byType: Record<LibraryResourceType, number> = {
      DOCUMENT: 0,
      PRESENTATION: 0,
      SPREADSHEET: 0,
      IMAGE: 0,
      VIDEO: 0,
      AUDIO: 0,
      EXTERNAL_LINK: 0,
      INTERACTIVE: 0,
    };

    const subjectMap = new Map<string, { subjectId: string; subjectName: string; count: number }>();
    const gradeMap = new Map<string, { gradeLevelId: string; gradeLevelName: string; count: number }>();

    for (const r of resources) {
      totalViews += r.viewCount || 0;
      totalDownloads += r.downloadCount || 0;
      totalCompletions += r.completionCount || 0;
      
      if (r.resourceType in byType) {
        byType[r.resourceType]++;
      }

      if (r.subjectId) {
        const sName = r.subjectName || this.subjects.get(r.subjectId)?.name || 'عام';
        const current = subjectMap.get(r.subjectId) || { subjectId: r.subjectId, subjectName: sName, count: 0 };
        current.count++;
        subjectMap.set(r.subjectId, current);
      }

      if (r.gradeLevelId) {
        const gName = r.gradeLevelName || this.gradeLevels.get(r.gradeLevelId)?.name || 'عام';
        const current = gradeMap.get(r.gradeLevelId) || { gradeLevelId: r.gradeLevelId, gradeLevelName: gName, count: 0 };
        current.count++;
        gradeMap.set(r.gradeLevelId, current);
      }
    }

    return {
      totalResources: resources.length,
      totalViews,
      totalDownloads,
      totalCompletions,
      byType,
      bySubject: Array.from(subjectMap.values()),
      byGrade: Array.from(gradeMap.values()),
    };
  }
}

export const db = new PlatformDatabase();
