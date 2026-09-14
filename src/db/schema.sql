-- =====================================================================
-- RTIQA Smart Education Platform - Production Database Schema (PostgreSQL)
-- Multi-Tenant Architecture with Row-Level Security (RLS) & Foreign Keys
-- =====================================================================

-- Enable UUID & Cryptographic extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Schema Migrations Tracking
CREATE TABLE IF NOT EXISTS _schema_migrations (
    id SERIAL PRIMARY KEY,
    version VARCHAR(64) UNIQUE NOT NULL,
    executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 1. Organizations (Tenants)
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(64) PRIMARY KEY,
    slug VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    legal_name VARCHAR(255),
    country_code VARCHAR(8) DEFAULT 'SA' NOT NULL,
    timezone VARCHAR(64) DEFAULT 'Asia/Riyadh' NOT NULL,
    locale VARCHAR(8) DEFAULT 'ar' NOT NULL,
    logo_url TEXT,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_active ON organizations(is_active);

-- 2. Academic Years
CREATE TABLE IF NOT EXISTS academic_years (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    is_current BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_academic_years_org ON academic_years(organization_id);

-- 3. Terms / Semesters
CREATE TABLE IF NOT EXISTS terms (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    academic_year_id VARCHAR(64) NOT NULL REFERENCES academic_years(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    is_current BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_terms_org_year ON terms(organization_id, academic_year_id);

-- 4. Grade Levels (Stages)
CREATE TABLE IF NOT EXISTS grade_levels (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    sequence_order INT DEFAULT 1 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grade_levels_org ON grade_levels(organization_id);

-- 5. Classrooms (Sections)
CREATE TABLE IF NOT EXISTS classrooms (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    grade_level_id VARCHAR(64) NOT NULL REFERENCES grade_levels(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    capacity INT DEFAULT 30,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_classrooms_org_grade ON classrooms(organization_id, grade_level_id);

-- 6. Users (Admins, Teachers, Students, Parents)
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('SUPER_ADMIN', 'ORG_ADMIN', 'TEACHER', 'STUDENT', 'PARENT')),
    avatar_url TEXT,
    phone VARCHAR(64),
    student_id_number VARCHAR(64),
    teacher_specialization VARCHAR(128),
    classroom_id VARCHAR(64) REFERENCES classrooms(id) ON DELETE SET NULL,
    email_verified BOOLEAN DEFAULT FALSE NOT NULL,
    phone_verified BOOLEAN DEFAULT FALSE NOT NULL,
    auth_providers JSONB DEFAULT '["email"]'::jsonb NOT NULL,
    google_id VARCHAR(128),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_users_org_email UNIQUE (organization_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_org_role ON users(organization_id, role);
CREATE INDEX IF NOT EXISTS idx_users_org_classroom ON users(organization_id, classroom_id);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);

-- 6.1 Organization Memberships (Multi-Tenant User Roles)
CREATE TABLE IF NOT EXISTS organization_memberships (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL CHECK (role IN ('SUPER_ADMIN', 'ORG_ADMIN', 'TEACHER', 'STUDENT', 'PARENT')),
    is_default BOOLEAN DEFAULT FALSE NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL CHECK (status IN ('ACTIVE', 'PENDING', 'REVOKED')),
    classroom_id VARCHAR(64) REFERENCES classrooms(id) ON DELETE SET NULL,
    student_id_number VARCHAR(64),
    teacher_specialization VARCHAR(128),
    joined_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_memberships_user_org UNIQUE (user_id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_user ON organization_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_org ON organization_memberships(organization_id);

-- 6.2 Password Reset Tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_resets_hash ON password_reset_tokens(token_hash);

-- 6.3 Email Verification Tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_verify_user ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verify_hash ON email_verification_tokens(token_hash);

-- 6.4 Phone Verification OTPs
CREATE TABLE IF NOT EXISTS phone_verification_otps (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    phone VARCHAR(64) NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    attempts_count INT DEFAULT 0 NOT NULL,
    max_attempts INT DEFAULT 5 NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_phone_otps_phone ON phone_verification_otps(phone);

-- 7. Subjects (Curriculum Master)
CREATE TABLE IF NOT EXISTS subjects (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(64) NOT NULL,
    color VARCHAR(32) DEFAULT '#10b981',
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_subjects_org_code UNIQUE (organization_id, code)
);

CREATE INDEX IF NOT EXISTS idx_subjects_org ON subjects(organization_id);

-- 8. Courses (Active Class Instances)
CREATE TABLE IF NOT EXISTS courses (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subject_id VARCHAR(64) NOT NULL REFERENCES subjects(id) ON DELETE RESTRICT,
    term_id VARCHAR(64) NOT NULL REFERENCES terms(id) ON DELETE RESTRICT,
    teacher_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    classroom_id VARCHAR(64) NOT NULL REFERENCES classrooms(id) ON DELETE RESTRICT,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_courses_org ON courses(organization_id);
CREATE INDEX IF NOT EXISTS idx_courses_teacher ON courses(organization_id, teacher_id);
CREATE INDEX IF NOT EXISTS idx_courses_classroom ON courses(organization_id, classroom_id);

-- 8.1 Teacher Assignments (Allocations of Teachers to Subjects & Classrooms)
CREATE TABLE IF NOT EXISTS teacher_assignments (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    teacher_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id VARCHAR(64) REFERENCES courses(id) ON DELETE CASCADE,
    subject_id VARCHAR(64) NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    classroom_id VARCHAR(64) NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
    academic_year_id VARCHAR(64) REFERENCES academic_years(id) ON DELETE SET NULL,
    role VARCHAR(32) DEFAULT 'PRIMARY_TEACHER' NOT NULL CHECK (role IN ('PRIMARY_TEACHER', 'ASSISTANT_TEACHER', 'SUBSTITUTE')),
    weekly_hours INT DEFAULT 4 NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL CHECK (status IN ('ACTIVE', 'INACTIVE')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_teacher_assignments_org ON teacher_assignments(organization_id);
CREATE INDEX IF NOT EXISTS idx_teacher_assignments_teacher ON teacher_assignments(organization_id, teacher_id);
CREATE INDEX IF NOT EXISTS idx_teacher_assignments_classroom ON teacher_assignments(organization_id, classroom_id);

-- 8.2 Student Enrollments (Active Classroom & Academic Year Rosters)
CREATE TABLE IF NOT EXISTS student_enrollments (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    classroom_id VARCHAR(64) NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
    academic_year_id VARCHAR(64) NOT NULL REFERENCES academic_years(id) ON DELETE CASCADE,
    roll_number VARCHAR(64),
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL CHECK (status IN ('ACTIVE', 'TRANSFERRED', 'SUSPENDED', 'GRADUATED')),
    enrolled_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_enrollments_student_year UNIQUE (organization_id, student_id, academic_year_id)
);

CREATE INDEX IF NOT EXISTS idx_student_enrollments_org ON student_enrollments(organization_id);
CREATE INDEX IF NOT EXISTS idx_student_enrollments_student ON student_enrollments(organization_id, student_id);
CREATE INDEX IF NOT EXISTS idx_student_enrollments_classroom ON student_enrollments(organization_id, classroom_id);

-- 8.3 Parent Student Links (Parent-Child Associations)
CREATE TABLE IF NOT EXISTS parent_student_links (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    relationship VARCHAR(32) DEFAULT 'FATHER' NOT NULL CHECK (relationship IN ('FATHER', 'MOTHER', 'GUARDIAN')),
    is_emergency_contact BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_parent_student_link UNIQUE (organization_id, parent_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_parent_student_parent ON parent_student_links(organization_id, parent_id);
CREATE INDEX IF NOT EXISTS idx_parent_student_student ON parent_student_links(organization_id, student_id);

-- 8.4 Student Records (Full SIS Profile, Medical, Emergency, Demographics)
CREATE TABLE IF NOT EXISTS student_records (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    national_id VARCHAR(64) NOT NULL,
    date_of_birth DATE NOT NULL,
    gender VARCHAR(16) NOT NULL CHECK (gender IN ('MALE', 'FEMALE')),
    blood_type VARCHAR(16) DEFAULT 'UNKNOWN' CHECK (blood_type IN ('A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'UNKNOWN')),
    nationality VARCHAR(64) DEFAULT 'سعودي',
    admission_date DATE NOT NULL,
    graduation_date DATE,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL CHECK (status IN ('ACTIVE', 'PROBATION', 'SUSPENDED', 'WITHDRAWN', 'TRANSFERRED', 'GRADUATED')),
    status_reason TEXT,
    medical_conditions TEXT,
    allergies TEXT,
    special_dietary_needs TEXT,
    emergency_contact_name VARCHAR(255) NOT NULL,
    emergency_contact_phone VARCHAR(64) NOT NULL,
    emergency_contact_relationship VARCHAR(64) NOT NULL,
    previous_school VARCHAR(255),
    special_needs_notes TEXT,
    gifted_program BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_student_records_org_student UNIQUE (organization_id, student_id),
    CONSTRAINT uq_student_records_org_national_id UNIQUE (organization_id, national_id)
);

CREATE INDEX IF NOT EXISTS idx_student_records_org ON student_records(organization_id);
CREATE INDEX IF NOT EXISTS idx_student_records_status ON student_records(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_student_records_national_id ON student_records(organization_id, national_id);

-- 8.5 Student Behavior Records (Conduct, Praises, Merits, Infractions)
CREATE TABLE IF NOT EXISTS student_behavior_records (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(32) NOT NULL CHECK (type IN ('POSITIVE_PRAISE', 'MERIT', 'MINOR_INFRACTION', 'MAJOR_INFRACTION', 'COUNSELING_REFERRAL', 'SUSPENSION_NOTICE')),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    points INT DEFAULT 0 NOT NULL,
    action_taken TEXT,
    incident_date DATE NOT NULL,
    recorded_by VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(32) DEFAULT 'OPEN' NOT NULL CHECK (status IN ('OPEN', 'RESOLVED', 'UNDER_REVIEW')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_student_behavior_org_student ON student_behavior_records(organization_id, student_id);
CREATE INDEX IF NOT EXISTS idx_student_behavior_date ON student_behavior_records(organization_id, incident_date DESC);

-- 8.6 Student Lifecycle Events (Audit History of Transitions & Promotions)
CREATE TABLE IF NOT EXISTS student_lifecycle_events (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    previous_status VARCHAR(32) NOT NULL,
    new_status VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL,
    action_by VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    effective_date DATE NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_student_lifecycle_org_student ON student_lifecycle_events(organization_id, student_id);

-- 9. Lessons (Course Units & Content)
CREATE TABLE IF NOT EXISTS lessons (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    course_id VARCHAR(64) NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content_html TEXT NOT NULL,
    media_url TEXT,
    attachments JSONB DEFAULT '[]'::jsonb,
    order_index INT DEFAULT 1 NOT NULL,
    is_published BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lessons_course ON lessons(organization_id, course_id, order_index);

-- 10. Assignments
CREATE TABLE IF NOT EXISTS assignments (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    course_id VARCHAR(64) NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    max_score NUMERIC(5,2) DEFAULT 100 NOT NULL,
    due_date TIMESTAMPTZ NOT NULL,
    attachments JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assignments_course ON assignments(organization_id, course_id);

-- 11. Submissions
CREATE TABLE IF NOT EXISTS submissions (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    assignment_id VARCHAR(64) NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    submission_text TEXT,
    file_attachment_url TEXT,
    score NUMERIC(5,2),
    teacher_feedback TEXT,
    submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    graded_at TIMESTAMPTZ,
    CONSTRAINT uq_submissions_assignment_student UNIQUE (assignment_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON submissions(organization_id, assignment_id);
CREATE INDEX IF NOT EXISTS idx_submissions_student ON submissions(organization_id, student_id);

-- 12. Attendance Sessions & Records
CREATE TABLE IF NOT EXISTS attendance_sessions (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    classroom_id VARCHAR(64) NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
    course_id VARCHAR(64) REFERENCES courses(id) ON DELETE SET NULL,
    date DATE NOT NULL,
    period_number INT DEFAULT 1,
    title VARCHAR(255),
    status VARCHAR(32) DEFAULT 'OPEN' NOT NULL CHECK (status IN ('OPEN', 'COMPLETED', 'LOCKED')),
    opened_by VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_attendance_sessions UNIQUE (organization_id, classroom_id, course_id, date, period_number)
);

CREATE INDEX IF NOT EXISTS idx_attendance_sessions_lookup ON attendance_sessions(organization_id, classroom_id, date);
CREATE INDEX IF NOT EXISTS idx_attendance_sessions_course ON attendance_sessions(organization_id, course_id, date);

CREATE TABLE IF NOT EXISTS attendance_records (
    id VARCHAR(128) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_id VARCHAR(64) REFERENCES attendance_sessions(id) ON DELETE SET NULL,
    course_id VARCHAR(64) REFERENCES courses(id) ON DELETE SET NULL,
    classroom_id VARCHAR(64) REFERENCES classrooms(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recorded_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    date DATE NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('PRESENT', 'ABSENT', 'LATE', 'EXCUSED')),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_attendance_records_unique UNIQUE (organization_id, classroom_id, student_id, date, course_id)
);

CREATE INDEX IF NOT EXISTS idx_attendance_lookup ON attendance_records(organization_id, classroom_id, date);
CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance_records(organization_id, student_id, date);
CREATE INDEX IF NOT EXISTS idx_attendance_session ON attendance_records(organization_id, session_id);

-- 12.1 Assessments (Comprehensive Academic Evaluations & Gradebook Model)
CREATE TABLE IF NOT EXISTS assessments (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    course_id VARCHAR(64) NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    subject_id VARCHAR(64) REFERENCES subjects(id) ON DELETE CASCADE,
    classroom_id VARCHAR(64) REFERENCES classrooms(id) ON DELETE CASCADE,
    term_id VARCHAR(64) REFERENCES terms(id) ON DELETE CASCADE,
    academic_year_id VARCHAR(64) REFERENCES academic_years(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(64) DEFAULT 'EXAM' NOT NULL,
    max_score NUMERIC(6,2) DEFAULT 100 NOT NULL,
    weight_percentage NUMERIC(5,2) DEFAULT 100 NOT NULL,
    due_date TIMESTAMPTZ,
    assessment_date DATE,
    status VARCHAR(32) DEFAULT 'PUBLISHED' NOT NULL CHECK (status IN ('DRAFT', 'PUBLISHED', 'CLOSED', 'ARCHIVED')),
    created_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_assessments_course_title UNIQUE (organization_id, course_id, title)
);

CREATE INDEX IF NOT EXISTS idx_assessments_course ON assessments(organization_id, course_id);
CREATE INDEX IF NOT EXISTS idx_assessments_classroom ON assessments(organization_id, classroom_id);
CREATE INDEX IF NOT EXISTS idx_assessments_term ON assessments(organization_id, term_id);

-- 12.2 Assessment Grades (Student Gradebook Entries)
CREATE TABLE IF NOT EXISTS assessment_grades (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    assessment_id VARCHAR(64) NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score NUMERIC(6,2) NOT NULL,
    feedback TEXT,
    graded_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    graded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_assessment_grades_student UNIQUE (organization_id, assessment_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_assessment_grades_assessment ON assessment_grades(organization_id, assessment_id);
CREATE INDEX IF NOT EXISTS idx_assessment_grades_student ON assessment_grades(organization_id, student_id);

-- 13. Audit Logs (Security & Compliance)
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64),
    user_email VARCHAR(255),
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(64) NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    ip_address VARCHAR(64),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time ON audit_logs(organization_id, timestamp DESC);

-- 14. Invitations (Secure User Onboarding & Invite Codes)
CREATE TABLE IF NOT EXISTS invitations (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('ORG_ADMIN', 'TEACHER', 'STUDENT', 'PARENT')),
    invite_code VARCHAR(64) UNIQUE NOT NULL,
    tokenHash VARCHAR(255),
    full_name VARCHAR(255),
    classroom_id VARCHAR(64) REFERENCES classrooms(id) ON DELETE SET NULL,
    teacher_specialization VARCHAR(128),
    student_id_number VARCHAR(64),
    created_by VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invitations_org ON invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_invitations_code ON invitations(invite_code);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(organization_id, email);

-- 15. AI Conversations (Rtiqa AI Engine)
CREATE TABLE IF NOT EXISTS ai_conversations (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    context_type VARCHAR(64) DEFAULT 'general' NOT NULL,
    context_id VARCHAR(64),
    system_prompt_type VARCHAR(64) DEFAULT 'general' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_conversations_org_user ON ai_conversations(organization_id, user_id, updated_at DESC);

-- 16. AI Messages
CREATE TABLE IF NOT EXISTS ai_messages (
    id VARCHAR(64) PRIMARY KEY,
    conversation_id VARCHAR(64) NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(16) NOT NULL CHECK (role IN ('system', 'user', 'assistant')),
    content TEXT NOT NULL,
    input_tokens INT DEFAULT 0 NOT NULL,
    output_tokens INT DEFAULT 0 NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_messages_conv ON ai_messages(organization_id, conversation_id, created_at ASC);

-- 17. AI Usage Records (Auditing, Limits & Quota Metering)
CREATE TABLE IF NOT EXISTS ai_usage (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    model VARCHAR(64) NOT NULL,
    feature_name VARCHAR(64) NOT NULL,
    input_tokens INT DEFAULT 0 NOT NULL,
    output_tokens INT DEFAULT 0 NOT NULL,
    estimated_cost NUMERIC(10, 6) DEFAULT 0 NOT NULL,
    latency_ms INT DEFAULT 0 NOT NULL,
    status VARCHAR(16) DEFAULT 'SUCCESS' NOT NULL CHECK (status IN ('SUCCESS', 'ERROR', 'RATE_LIMITED', 'BLOCKED')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_usage_org_time ON ai_usage(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_usage_org_user ON ai_usage(organization_id, user_id);

-- 18. AI Document Chunks (RAG Foundation)
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS ai_document_chunks (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    document_id VARCHAR(64) NOT NULL,
    source_id VARCHAR(64),
    source_type VARCHAR(64),
    source_visibility VARCHAR(64),
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    course_ids VARCHAR(64)[],
    embedding_model VARCHAR(128) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    chunk_index INT DEFAULT 0 NOT NULL,
    embedding vector(768),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ai_conv_privacy CHECK (source_type != 'AI_CONVERSATION' OR user_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_ai_chunks_org_source ON ai_document_chunks(organization_id, source_id);
CREATE INDEX IF NOT EXISTS idx_ai_chunks_user_conv ON ai_document_chunks(user_id) WHERE source_type = 'AI_CONVERSATION';
CREATE INDEX IF NOT EXISTS idx_ai_chunks_embedding ON ai_document_chunks USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);

-- 19. Storage Objects (Multi-Tenant Secure Object Storage Metadata)
CREATE TABLE IF NOT EXISTS storage_objects (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(128) NOT NULL,
    size_bytes BIGINT NOT NULL,
    checksum VARCHAR(128),
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(64) NOT NULL,
    uploaded_by VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(32) DEFAULT 'PENDING' NOT NULL CHECK (status IN ('PENDING', 'UPLOADED', 'FAILED', 'DELETED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_storage_objects_org_res ON storage_objects(organization_id, resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_storage_objects_key ON storage_objects(object_key);
CREATE INDEX IF NOT EXISTS idx_storage_objects_uploader ON storage_objects(organization_id, uploaded_by);
CREATE INDEX IF NOT EXISTS idx_storage_objects_status ON storage_objects(organization_id, status);

-- 20. Curriculum Units (Structured Course Units / Chapters)
CREATE TABLE IF NOT EXISTS curriculum_units (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    course_id VARCHAR(64) NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    order_index INT DEFAULT 1 NOT NULL,
    is_published BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_curriculum_units_course ON curriculum_units(organization_id, course_id, order_index);

-- Ensure lessons support unit_id and resource_ids
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='lessons' AND column_name='unit_id') THEN
        ALTER TABLE lessons ADD COLUMN unit_id VARCHAR(64) REFERENCES curriculum_units(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='lessons' AND column_name='resource_ids') THEN
        ALTER TABLE lessons ADD COLUMN resource_ids JSONB DEFAULT '[]'::jsonb;
    END IF;
END $$;

-- 21. Digital Library Resources (Multi-Format Educational Assets)
CREATE TABLE IF NOT EXISTS library_resources (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    resource_type VARCHAR(32) NOT NULL CHECK (resource_type IN ('DOCUMENT', 'PRESENTATION', 'SPREADSHEET', 'IMAGE', 'VIDEO', 'AUDIO', 'EXTERNAL_LINK', 'INTERACTIVE')),
    format VARCHAR(64) NOT NULL,
    subject_id VARCHAR(64) REFERENCES subjects(id) ON DELETE SET NULL,
    grade_level_id VARCHAR(64) REFERENCES grade_levels(id) ON DELETE SET NULL,
    course_id VARCHAR(64) REFERENCES courses(id) ON DELETE SET NULL,
    unit_id VARCHAR(64) REFERENCES curriculum_units(id) ON DELETE SET NULL,
    lesson_id VARCHAR(64) REFERENCES lessons(id) ON DELETE SET NULL,
    storage_object_id VARCHAR(64) REFERENCES storage_objects(id) ON DELETE SET NULL,
    external_url TEXT,
    file_size BIGINT DEFAULT 0,
    file_type VARCHAR(128),
    tags JSONB DEFAULT '[]'::jsonb,
    uploaded_by VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    author_name VARCHAR(255),
    visibility VARCHAR(32) DEFAULT 'PUBLIC_SCHOOL' NOT NULL CHECK (visibility IN ('PUBLIC_SCHOOL', 'COURSE_STUDENTS', 'TEACHERS_ONLY', 'PRIVATE')),
    status VARCHAR(32) DEFAULT 'PUBLISHED' NOT NULL CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
    view_count INT DEFAULT 0 NOT NULL,
    download_count INT DEFAULT 0 NOT NULL,
    completion_count INT DEFAULT 0 NOT NULL,
    ai_searchable BOOLEAN DEFAULT TRUE NOT NULL,
    ai_summary TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_library_resources_org ON library_resources(organization_id);
CREATE INDEX IF NOT EXISTS idx_library_resources_course ON library_resources(organization_id, course_id);
CREATE INDEX IF NOT EXISTS idx_library_resources_subject ON library_resources(organization_id, subject_id);
CREATE INDEX IF NOT EXISTS idx_library_resources_grade ON library_resources(organization_id, grade_level_id);
CREATE INDEX IF NOT EXISTS idx_library_resources_unit ON library_resources(organization_id, unit_id);
CREATE INDEX IF NOT EXISTS idx_library_resources_type ON library_resources(organization_id, resource_type);
CREATE INDEX IF NOT EXISTS idx_library_resources_status ON library_resources(organization_id, status);

-- 22. Resource Learning Activity (Tracking Student & Teacher Interactions)
CREATE TABLE IF NOT EXISTS resource_activities (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id VARCHAR(64) NOT NULL REFERENCES library_resources(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_role VARCHAR(32) NOT NULL,
    action VARCHAR(32) NOT NULL CHECK (action IN ('VIEWED', 'DOWNLOADED', 'COMPLETED', 'ATTACHED')),
    course_id VARCHAR(64) REFERENCES courses(id) ON DELETE SET NULL,
    lesson_id VARCHAR(64) REFERENCES lessons(id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_resource_activities_org_res ON resource_activities(organization_id, resource_id);
CREATE INDEX IF NOT EXISTS idx_resource_activities_user ON resource_activities(organization_id, user_id);
CREATE INDEX IF NOT EXISTS idx_resource_activities_action ON resource_activities(organization_id, action);

-- =====================================================================
-- Row-Level Security (RLS) Policies & Enforcement
-- Multi-tenant isolation at the PostgreSQL storage engine level
-- Tenant is identified by session variable `app.current_tenant_id`
-- =====================================================================

-- Enable & Force RLS on all tenant-bound tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE academic_years ENABLE ROW LEVEL SECURITY;
ALTER TABLE terms ENABLE ROW LEVEL SECURITY;
ALTER TABLE grade_levels ENABLE ROW LEVEL SECURITY;
ALTER TABLE classrooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE courses ENABLE ROW LEVEL SECURITY;
ALTER TABLE lessons ENABLE ROW LEVEL SECURITY;
ALTER TABLE assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_document_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE curriculum_units ENABLE ROW LEVEL SECURITY;
ALTER TABLE library_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_activities ENABLE ROW LEVEL SECURITY;

-- 1. Organizations Policy: Accessible if matching session tenant or if in global/unbound resolution mode
DROP POLICY IF EXISTS tenant_isolation_org ON organizations;
CREATE POLICY tenant_isolation_org ON organizations
    USING (
        id = NULLIF(current_setting('app.current_tenant_id', true), '')
        OR NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
    );

-- 2. Academic Years Policy
DROP POLICY IF EXISTS tenant_isolation_academic_years ON academic_years;
CREATE POLICY tenant_isolation_academic_years ON academic_years
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 3. Terms Policy
DROP POLICY IF EXISTS tenant_isolation_terms ON terms;
CREATE POLICY tenant_isolation_terms ON terms
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 4. Grade Levels Policy
DROP POLICY IF EXISTS tenant_isolation_grade_levels ON grade_levels;
CREATE POLICY tenant_isolation_grade_levels ON grade_levels
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 5. Classrooms Policy
DROP POLICY IF EXISTS tenant_isolation_classrooms ON classrooms;
CREATE POLICY tenant_isolation_classrooms ON classrooms
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 6. Users Policy
DROP POLICY IF EXISTS tenant_isolation_users ON users;
CREATE POLICY tenant_isolation_users ON users
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 7. Subjects Policy
DROP POLICY IF EXISTS tenant_isolation_subjects ON subjects;
CREATE POLICY tenant_isolation_subjects ON subjects
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 8. Courses Policy
DROP POLICY IF EXISTS tenant_isolation_courses ON courses;
CREATE POLICY tenant_isolation_courses ON courses
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 9. Lessons Policy
DROP POLICY IF EXISTS tenant_isolation_lessons ON lessons;
CREATE POLICY tenant_isolation_lessons ON lessons
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 10. Assignments Policy
DROP POLICY IF EXISTS tenant_isolation_assignments ON assignments;
CREATE POLICY tenant_isolation_assignments ON assignments
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 11. Submissions Policy
DROP POLICY IF EXISTS tenant_isolation_submissions ON submissions;
CREATE POLICY tenant_isolation_submissions ON submissions
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 12. Attendance Records Policy
DROP POLICY IF EXISTS tenant_isolation_attendance ON attendance_records;
CREATE POLICY tenant_isolation_attendance ON attendance_records
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 13. Audit Logs Policy
DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 14. Invitations Policy
DROP POLICY IF EXISTS tenant_isolation_invitations ON invitations;
CREATE POLICY tenant_isolation_invitations ON invitations
    USING (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')
        OR NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')
        OR NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
    );

-- 15. AI Conversations Policy
DROP POLICY IF EXISTS tenant_isolation_ai_conversations ON ai_conversations;
CREATE POLICY tenant_isolation_ai_conversations ON ai_conversations
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 16. AI Messages Policy
DROP POLICY IF EXISTS tenant_isolation_ai_messages ON ai_messages;
CREATE POLICY tenant_isolation_ai_messages ON ai_messages
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 17. AI Usage Policy
DROP POLICY IF EXISTS tenant_isolation_ai_usage ON ai_usage;
CREATE POLICY tenant_isolation_ai_usage ON ai_usage
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 18. AI Document Chunks Policy
DROP POLICY IF EXISTS tenant_isolation_ai_document_chunks ON ai_document_chunks;
CREATE POLICY tenant_isolation_ai_document_chunks ON ai_document_chunks
    USING (
        (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '') OR organization_id = 'platform')
        AND (source_type != 'AI_CONVERSATION' OR source_type IS NULL OR user_id = NULLIF(current_setting('app.current_user_id', true), ''))
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')
        AND (source_type != 'AI_CONVERSATION' OR source_type IS NULL OR user_id = NULLIF(current_setting('app.current_user_id', true), ''))
    );

-- 19. Organization Memberships Policy
ALTER TABLE organization_memberships ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_org_memberships ON organization_memberships;
CREATE POLICY tenant_isolation_org_memberships ON organization_memberships
    USING (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')
        OR user_id = NULLIF(current_setting('app.current_user_id', true), '')
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')
    );

-- 20. Teacher Assignments Policy
ALTER TABLE teacher_assignments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_teacher_assignments ON teacher_assignments;
CREATE POLICY tenant_isolation_teacher_assignments ON teacher_assignments
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 21. Student Enrollments Policy
ALTER TABLE student_enrollments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_student_enrollments ON student_enrollments;
CREATE POLICY tenant_isolation_student_enrollments ON student_enrollments
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 22. Parent Student Links Policy
ALTER TABLE parent_student_links ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_parent_student_links ON parent_student_links;
CREATE POLICY tenant_isolation_parent_student_links ON parent_student_links
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 23. Student Records Policy
ALTER TABLE student_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_student_records ON student_records;
CREATE POLICY tenant_isolation_student_records ON student_records
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 24. Student Behavior Records Policy
ALTER TABLE student_behavior_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_student_behavior_records ON student_behavior_records;
CREATE POLICY tenant_isolation_student_behavior_records ON student_behavior_records
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 25. Student Lifecycle Events Policy
ALTER TABLE student_lifecycle_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_student_lifecycle_events ON student_lifecycle_events;
CREATE POLICY tenant_isolation_student_lifecycle_events ON student_lifecycle_events
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 26. Attendance Sessions Policy
ALTER TABLE attendance_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_attendance_sessions ON attendance_sessions;
CREATE POLICY tenant_isolation_attendance_sessions ON attendance_sessions
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 27. Assessments Policy
ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_assessments ON assessments;
CREATE POLICY tenant_isolation_assessments ON assessments
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 28. Assessment Grades Policy
ALTER TABLE assessment_grades ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_assessment_grades ON assessment_grades;
CREATE POLICY tenant_isolation_assessment_grades ON assessment_grades
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 29. Storage Objects Policy (Multi-Tenant Object Isolation)
ALTER TABLE storage_objects ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_storage_objects ON storage_objects;
CREATE POLICY tenant_isolation_storage_objects ON storage_objects
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 30. Curriculum Units Policy (Multi-Tenant Unit Isolation)
ALTER TABLE curriculum_units ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_curriculum_units ON curriculum_units;
CREATE POLICY tenant_isolation_curriculum_units ON curriculum_units
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 31. Library Resources Policy (Multi-Tenant Digital Resource Isolation)
ALTER TABLE library_resources ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_library_resources ON library_resources;
CREATE POLICY tenant_isolation_library_resources ON library_resources
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 32. Resource Activities Policy (Multi-Tenant Learning Activity Isolation)
ALTER TABLE resource_activities ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_resource_activities ON resource_activities;
CREATE POLICY tenant_isolation_resource_activities ON resource_activities
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- 33. Student Profiles (Decoupled Institutional Student Dossiers)
CREATE TABLE IF NOT EXISTS student_profiles (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    first_name VARCHAR(128) NOT NULL,
    last_name VARCHAR(128) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    student_id_number VARCHAR(64),
    date_of_birth DATE,
    gender VARCHAR(16) DEFAULT 'OTHER',
    grade_level_id VARCHAR(64) REFERENCES grade_levels(id) ON DELETE SET NULL,
    classroom_id VARCHAR(64) REFERENCES classrooms(id) ON DELETE SET NULL,
    admission_date DATE,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL,
    claim_token_hash VARCHAR(128),
    claim_token_expires_at TIMESTAMPTZ,
    is_claimed BOOLEAN DEFAULT FALSE NOT NULL,
    claimed_by_user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_student_profiles_org ON student_profiles(organization_id);
CREATE INDEX IF NOT EXISTS idx_student_profiles_claimed_user ON student_profiles(claimed_by_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_student_profiles_claim_user ON student_profiles (organization_id, claimed_by_user_id) WHERE claimed_by_user_id IS NOT NULL;

-- 34. Parent Link Tokens (Secure Temporary Link Tokens)
CREATE TABLE IF NOT EXISTS parent_link_tokens (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    student_profile_id VARCHAR(64) NOT NULL REFERENCES student_profiles(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL,
    relationship VARCHAR(32) DEFAULT 'GUARDIAN' NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    used_by_user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    used_at TIMESTAMPTZ,
    created_by VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_parent_link_tokens_org ON parent_link_tokens(organization_id);
CREATE INDEX IF NOT EXISTS idx_parent_link_tokens_hash ON parent_link_tokens(token_hash);

-- RLS Policies for new tables
ALTER TABLE student_profiles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_student_profiles ON student_profiles;
CREATE POLICY tenant_isolation_student_profiles ON student_profiles
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

ALTER TABLE parent_link_tokens ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_parent_link_tokens ON parent_link_tokens;
CREATE POLICY tenant_isolation_parent_link_tokens ON parent_link_tokens
    USING (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), ''));

-- Force RLS for the application role as well as table owners.
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE academic_years FORCE ROW LEVEL SECURITY;
ALTER TABLE terms FORCE ROW LEVEL SECURITY;
ALTER TABLE grade_levels FORCE ROW LEVEL SECURITY;
ALTER TABLE classrooms FORCE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE organization_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE subjects FORCE ROW LEVEL SECURITY;
ALTER TABLE courses FORCE ROW LEVEL SECURITY;
ALTER TABLE teacher_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE student_enrollments FORCE ROW LEVEL SECURITY;
ALTER TABLE parent_student_links FORCE ROW LEVEL SECURITY;
ALTER TABLE student_records FORCE ROW LEVEL SECURITY;
ALTER TABLE student_behavior_records FORCE ROW LEVEL SECURITY;
ALTER TABLE student_lifecycle_events FORCE ROW LEVEL SECURITY;
ALTER TABLE lessons FORCE ROW LEVEL SECURITY;
ALTER TABLE assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE submissions FORCE ROW LEVEL SECURITY;
ALTER TABLE attendance_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE attendance_records FORCE ROW LEVEL SECURITY;
ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
ALTER TABLE assessment_grades FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE ai_conversations FORCE ROW LEVEL SECURITY;
ALTER TABLE ai_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE ai_usage FORCE ROW LEVEL SECURITY;
ALTER TABLE ai_document_chunks FORCE ROW LEVEL SECURITY;
ALTER TABLE storage_objects FORCE ROW LEVEL SECURITY;
ALTER TABLE curriculum_units FORCE ROW LEVEL SECURITY;
ALTER TABLE library_resources FORCE ROW LEVEL SECURITY;
ALTER TABLE resource_activities FORCE ROW LEVEL SECURITY;
ALTER TABLE student_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE parent_link_tokens FORCE ROW LEVEL SECURITY;







