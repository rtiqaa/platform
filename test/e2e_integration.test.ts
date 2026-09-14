import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createApp } from '../server';
import { db } from '../server/platform/db';
import { checkPostgresConnection, closePostgresPool } from '../src/db/postgres';

describe('Rtiqa Platform - E2E Production Integration & Database Lifecycle Suite', () => {
  let server: any;
  let baseUrl: string;

  before(async () => {
    process.env.NODE_ENV = 'test';
    const app = await createApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const port = (server.address() as any).port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      if (typeof server.closeAllConnections === 'function') {
        server.closeAllConnections();
      }
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await closePostgresPool();
  });

  describe('1. Health & Database Engine Verification', () => {
    it('Root health endpoint returns 200 with database engine status', async () => {
      const res = await fetch(`${baseUrl}/api/health`);
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'ok');
      assert.strictEqual(data.service, 'rtiqa-api-gateway');
      assert.ok(data.database);
    });

    it('Platform API v1 health endpoint returns engine diagnostic info', async () => {
      const res = await fetch(`${baseUrl}/api/v1/health`);
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'ok');
      assert.strictEqual(data.service, 'rtiqa-platform-api');
      assert.ok(data.database);
    });

    it('PostgreSQL connection checker function handles environment cleanly', async () => {
      const status = await checkPostgresConnection();
      assert.ok(typeof status.connected === 'boolean');
      assert.ok(typeof status.fallbackToMemory === 'boolean');
      assert.ok(typeof status.message === 'string');
    });
  });

  describe('2. Complete End-to-End School Onboarding & Academic Flow', () => {
    let onboardedOrgToken: string;
    let onboardedOrgId: string;
    let onboardedYearId: string;
    let onboardedGradeId: string;
    let onboardedClassroomId: string;
    let onboardedSubjectId: string;
    let onboardedTeacherId: string;
    let onboardedTeacherToken: string;
    let onboardedStudentId: string;
    let onboardedStudentToken: string;
    let onboardedCourseId: string;
    let onboardedLessonId: string;
    let onboardedAssignmentId: string;
    let onboardedSubmissionId: string;

    it('Step 1: Onboard a brand new School (Al-Noor Private School)', async () => {
      const slug = `alnoor-${Date.now()}`;
      const res = await fetch(`${baseUrl}/api/v1/auth/register-school`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          schoolName: 'مدارس النور الأهلية الحديثة',
          slug,
          adminName: 'أ. عبد الرحمن السالم',
          adminEmail: `admin@${slug}.edu.sa`,
          countryCode: 'SA',
        }),
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.token);
      assert.strictEqual(data.user.role, 'ORG_ADMIN');
      assert.strictEqual(data.organization.name, 'مدارس النور الأهلية الحديثة');

      onboardedOrgToken = data.token;
      onboardedOrgId = data.organization.id;
    });

    it('Step 2: Create Academic Year, Term, Grade Level, Classroom, and Subject', async () => {
      // Create Academic Year
      const yearRes = await fetch(`${baseUrl}/api/v1/academic/years`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedOrgToken}`,
        },
        body: JSON.stringify({
          name: '2026-2027 العام الدراسي',
          startDate: '2026-09-01',
          endDate: '2027-06-30',
          isCurrent: true,
        }),
      });
      assert.strictEqual(yearRes.status, 201);
      const yearData = await yearRes.json();
      onboardedYearId = yearData.data.id;

      // Create Term
      const termRes = await fetch(`${baseUrl}/api/v1/academic/terms`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedOrgToken}`,
        },
        body: JSON.stringify({
          academicYearId: onboardedYearId,
          name: 'الفصل الأول 2026',
          startDate: '2026-09-01',
          endDate: '2027-01-15',
          isCurrent: true,
        }),
      });
      assert.strictEqual(termRes.status, 201);
      const termData = await termRes.json();
      const termId = termData.data.id;

      // Create Grade Level
      const gradeRes = await fetch(`${baseUrl}/api/v1/academic/grades`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedOrgToken}`,
        },
        body: JSON.stringify({
          name: 'الصف الأول الثانوي',
          sequenceOrder: 10,
        }),
      });
      assert.strictEqual(gradeRes.status, 201);
      const gradeData = await gradeRes.json();
      onboardedGradeId = gradeData.data.id;

      // Create Classroom
      const classRes = await fetch(`${baseUrl}/api/v1/academic/classrooms`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedOrgToken}`,
        },
        body: JSON.stringify({
          gradeLevelId: onboardedGradeId,
          name: '10-علمي-1',
          capacity: 30,
        }),
      });
      assert.strictEqual(classRes.status, 201);
      const classData = await classRes.json();
      onboardedClassroomId = classData.data.id;

      // Create Subject
      const subjRes = await fetch(`${baseUrl}/api/v1/academic/subjects`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedOrgToken}`,
        },
        body: JSON.stringify({
          name: 'الذكاء الاصطناعي وعلوم البيانات',
          code: 'AI-101',
          color: '#6366f1',
          description: 'مقدمة في خوارزميات الذكاء الاصطناعي ومعالجة البيانات',
        }),
      });
      assert.strictEqual(subjRes.status, 201);
      const subjData = await subjRes.json();
      onboardedSubjectId = subjData.data.id;
    });

    it('Step 3: Create Teacher and Student, then authenticate them', async () => {
      // Create Teacher
      const teacherRes = await fetch(`${baseUrl}/api/v1/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedOrgToken}`,
        },
        body: JSON.stringify({
          fullName: 'أ. خالد التميمي',
          email: 'khaled.tamimi@alnoor.edu.sa',
          role: 'TEACHER',
          teacherSpecialization: 'علوم الحاسب والذكاء الاصطناعي',
        }),
      });
      assert.strictEqual(teacherRes.status, 200);
      const teacherData = await teacherRes.json();
      onboardedTeacherId = teacherData.data.id;

      // Create Student
      const studentRes = await fetch(`${baseUrl}/api/v1/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedOrgToken}`,
        },
        body: JSON.stringify({
          fullName: 'محمد علي القرني',
          email: 'mohammed.qarni@alnoor.edu.sa',
          role: 'STUDENT',
          studentIdNumber: 'ALN-2026-001',
          classroomId: onboardedClassroomId,
        }),
      });
      assert.strictEqual(studentRes.status, 200);
      const studentData = await studentRes.json();
      onboardedStudentId = studentData.data.id;

      // Login Teacher
      const tLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'khaled.tamimi@alnoor.edu.sa',
        }),
      });
      assert.strictEqual(tLoginRes.status, 200);
      const tLoginData = await tLoginRes.json();
      assert.strictEqual(tLoginData.success, true);
      onboardedTeacherToken = tLoginData.token;

      // Login Student
      const sLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'mohammed.qarni@alnoor.edu.sa',
        }),
      });
      assert.strictEqual(sLoginRes.status, 200);
      const sLoginData = await sLoginRes.json();
      assert.strictEqual(sLoginData.success, true);
      onboardedStudentToken = sLoginData.token;
    });

    it('Step 4: Teacher creates Course and publishes a Lesson', async () => {
      // Get terms to link
      const termsRes = await fetch(`${baseUrl}/api/v1/academic/terms`, {
        headers: { Authorization: `Bearer ${onboardedTeacherToken}` },
      });
      const termsData = await termsRes.json();
      const termId = termsData.data[0].id;

      // Create Course
      const courseRes = await fetch(`${baseUrl}/api/v1/courses`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedTeacherToken}`,
        },
        body: JSON.stringify({
          subjectId: onboardedSubjectId,
          termId,
          classroomId: onboardedClassroomId,
          title: 'الذكاء الاصطناعي - الصف العاشر',
          description: 'مقرر تطبيقي عملي',
        }),
      });
      assert.strictEqual(courseRes.status, 200);
      const courseData = await courseRes.json();
      assert.strictEqual(courseData.success, true);
      onboardedCourseId = courseData.data.id;

      // Create Lesson
      const lessonRes = await fetch(`${baseUrl}/api/v1/lessons`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedTeacherToken}`,
        },
        body: JSON.stringify({
          courseId: onboardedCourseId,
          title: 'مقدمة في الشبكات العصبية الاصطناعية',
          contentHtml: '<p>شرح البيرسبترون والطبقات الخفية.</p>',
          orderIndex: 1,
          isPublished: true,
        }),
      });
      assert.strictEqual(lessonRes.status, 200);
      const lessonData = await lessonRes.json();
      assert.strictEqual(lessonData.success, true);
      onboardedLessonId = lessonData.data.id;
    });

    it('Step 5: Teacher creates Assignment, Student submits, Teacher grades', async () => {
      // Create Assignment
      const asgRes = await fetch(`${baseUrl}/api/v1/assignments`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedTeacherToken}`,
        },
        body: JSON.stringify({
          courseId: onboardedCourseId,
          title: 'الواجب الأول: تدريب نموذج تصنيف مبسط',
          description: 'بناء نموذج وتدوين نسبة الدقة.',
          maxScore: 20,
          dueDate: '2026-11-01T23:59:00Z',
        }),
      });
      assert.strictEqual(asgRes.status, 200);
      const asgData = await asgRes.json();
      assert.strictEqual(asgData.success, true);
      onboardedAssignmentId = asgData.data.id;

      // Course detail includes all tenant-scoped dependent data.
      const detailRes = await fetch(`${baseUrl}/api/v1/courses/${onboardedCourseId}`, {
        headers: { Authorization: `Bearer ${onboardedTeacherToken}` },
      });
      assert.strictEqual(detailRes.status, 200);
      const detailData = await detailRes.json();
      assert.strictEqual(detailData.success, true);
      assert.ok(detailData.data.lessons.some((lesson: any) => lesson.id === onboardedLessonId));
      assert.ok(detailData.data.assignments.some((assignment: any) => assignment.id === onboardedAssignmentId));
      assert.ok(detailData.data.students.some((student: any) => student.id === onboardedStudentId));
      assert.ok(detailData.data.teachers.some((teacher: any) => teacher.id === onboardedTeacherId));

      // Student views Assignment
      const studentAsgRes = await fetch(`${baseUrl}/api/v1/assignments/${onboardedAssignmentId}`, {
        headers: { Authorization: `Bearer ${onboardedStudentToken}` },
      });
      assert.strictEqual(studentAsgRes.status, 200);
      const studentAsgData = await studentAsgRes.json();
      assert.strictEqual(studentAsgData.data.title, 'الواجب الأول: تدريب نموذج تصنيف مبسط');

      // Student submits Assignment
      const submitRes = await fetch(`${baseUrl}/api/v1/assignments/${onboardedAssignmentId}/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedStudentToken}`,
        },
        body: JSON.stringify({
          submissionText: 'تم تدريب النموذج ووصلت الدقة إلى 94.5%',
          fileAttachmentUrl: 'https://example.com/submission_model.py',
        }),
      });
      assert.strictEqual(submitRes.status, 200);
      const submitData = await submitRes.json();
      assert.strictEqual(submitData.success, true);
      onboardedSubmissionId = submitData.data.id;

      // Teacher grades Submission
      const gradeRes = await fetch(`${baseUrl}/api/v1/assignments/submissions/${onboardedSubmissionId}/grade`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedTeacherToken}`,
        },
        body: JSON.stringify({
          score: 19,
          teacherFeedback: 'أداء متميز وتطبيق دقيق!',
        }),
      });
      assert.strictEqual(gradeRes.status, 200);
      const gradeData = await gradeRes.json();
      assert.strictEqual(gradeData.success, true);
      assert.strictEqual(gradeData.data.score, 19);
    });

    it('Step 6: Gradebook calculation & Student Grades view reflect accurate scores', async () => {
      // Teacher views course Gradebook Matrix
      const gbRes = await fetch(`${baseUrl}/api/v1/gradebook?courseId=${onboardedCourseId}`, {
        headers: { Authorization: `Bearer ${onboardedTeacherToken}` },
      });
      assert.strictEqual(gbRes.status, 200);
      const gbData = await gbRes.json();
      assert.strictEqual(gbData.success, true);
      assert.ok(gbData.data.matrix.length >= 1);
      const studentRow = gbData.data.matrix.find((m: any) => m.studentId === onboardedStudentId);
      assert.ok(studentRow);
      assert.strictEqual(studentRow.totalEarned, 19);
      assert.strictEqual(studentRow.totalMax, 20);
      assert.strictEqual(studentRow.averagePercent, 95);

      // Student views their own grades
      const myGradesRes = await fetch(`${baseUrl}/api/v1/gradebook/my-grades`, {
        headers: { Authorization: `Bearer ${onboardedStudentToken}` },
      });
      assert.strictEqual(myGradesRes.status, 200);
      const myGradesData = await myGradesRes.json();
      assert.strictEqual(myGradesData.success, true);
      const courseBreakdown = myGradesData.data.breakdown.find((b: any) => b.courseId === onboardedCourseId);
      assert.ok(courseBreakdown);
      assert.strictEqual(courseBreakdown.earned, 19);
      assert.strictEqual(courseBreakdown.max, 20);
      assert.strictEqual(courseBreakdown.average, 95);
    });

    it('Step 7: Teacher records Attendance batch and Student views attendance rate', async () => {
      const today = new Date().toISOString().split('T')[0];
      const attRes = await fetch(`${baseUrl}/api/v1/attendance`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${onboardedTeacherToken}`,
        },
        body: JSON.stringify({
          courseId: onboardedCourseId,
          classroomId: onboardedClassroomId,
          date: today,
          records: [
            {
              studentId: onboardedStudentId,
              status: 'PRESENT',
              notes: 'حضور مبكر ومشارك',
            },
          ],
        }),
      });
      assert.strictEqual(attRes.status, 200);
      const attData = await attRes.json();
      assert.strictEqual(attData.success, true);
      assert.strictEqual(attData.data.length, 1);

      // Student views attendance summary
      const sumRes = await fetch(`${baseUrl}/api/v1/attendance/summary`, {
        headers: { Authorization: `Bearer ${onboardedStudentToken}` },
      });
      assert.strictEqual(sumRes.status, 200);
      const sumData = await sumRes.json();
      assert.strictEqual(sumData.success, true);
      assert.strictEqual(sumData.data.present, 1);
      assert.strictEqual(sumData.data.attendanceRate, 100);
    });
  });

  describe('3. Strict Cross-Tenant Multi-Tenancy Isolation Verification', () => {
    it('Horizon School Admin cannot see Al-Noor or Elite users', async () => {
      const loginH = await fetch(`${baseUrl}/api/v1/auth/demo-switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ persona: 'admin', tenantSlug: 'horizon' }),
      });
      const dataH = await loginH.json();
      const horizonToken = dataH.token;

      const usersRes = await fetch(`${baseUrl}/api/v1/users`, {
        headers: { Authorization: `Bearer ${horizonToken}` },
      });
      const usersData = await usersRes.json();
      assert.strictEqual(usersData.success, true);

      // Verify all users returned belong exclusively to Horizon
      usersData.data.forEach((u: any) => {
        assert.ok(!u.email.includes('elite.edu.sa'));
        assert.ok(!u.email.includes('alnoor.edu.sa'));
      });
    });

    it('Horizon Teacher cannot access courses from Elite School', async () => {
      const loginH = await fetch(`${baseUrl}/api/v1/auth/demo-switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ persona: 'teacher', tenantSlug: 'horizon' }),
      });
      const dataH = await loginH.json();

      const coursesRes = await fetch(`${baseUrl}/api/v1/courses`, {
        headers: { Authorization: `Bearer ${dataH.token}` },
      });
      const coursesData = await coursesRes.json();
      assert.strictEqual(coursesData.success, true);

      // Must not contain any Elite courses
      coursesData.data.forEach((c: any) => {
        assert.ok(c.title.includes('الرياضيات') || c.title.includes('الفيزياء'));
        assert.ok(!c.title.includes('Elite'));
      });
    });
  });
});
