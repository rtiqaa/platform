import express from 'express';
import { db } from '../db.ts';
import type { PlatformRequest } from '../auth.ts';
import { requireAuth, requireRoles } from '../auth.ts';

export const academicRouter = express.Router();

academicRouter.use(requireAuth);

// ==========================================
// 1. Academic Years
// ==========================================

academicRouter.get('/years', async (req: PlatformRequest, res: express.Response) => {
  try {
    const years = await db.getAcademicYearsAsync(req.organization!.id);
    res.json({ success: true, data: years });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.get('/years/:id', async (req: PlatformRequest, res: express.Response) => {
  try {
    const year = await db.getAcademicYearByIdAsync(req.params.id, req.organization!.id);
    if (!year) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'السنة الأكاديمية غير موجودة' });
    }
    res.json({ success: true, data: year });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/years', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const { name, startDate, endDate, isCurrent } = req.body;
    if (!name || !startDate || !endDate) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_FIELDS',
        message: 'اسم السنة الأكاديمية وتواريخ البداية والنهاية مطلوبة',
      });
    }
    const year = await db.createAcademicYearAsync({
      organizationId: req.organization!.id,
      name: String(name).trim(),
      startDate,
      endDate,
      isCurrent: Boolean(isCurrent),
    });
    res.status(201).json({ success: true, data: year });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.put('/years/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const existing = await db.getAcademicYearByIdAsync(req.params.id, req.organization!.id);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'السنة الأكاديمية غير موجودة' });
    }
    const { name, startDate, endDate, isCurrent } = req.body;
    const updated = await db.updateAcademicYearAsync(req.params.id, req.organization!.id, {
      name: name ? String(name).trim() : undefined,
      startDate,
      endDate,
      isCurrent: isCurrent !== undefined ? Boolean(isCurrent) : undefined,
    });
    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/years/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const success = await db.deleteAcademicYearAsync(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'السنة الأكاديمية غير موجودة' });
    }
    res.json({ success: true, message: 'تم حذف السنة الأكاديمية بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 2. Terms
// ==========================================

academicRouter.get('/terms', async (req: PlatformRequest, res: express.Response) => {
  try {
    const yearId = req.query.yearId as string | undefined;
    const terms = await db.getTermsAsync(req.organization!.id, yearId);
    res.json({ success: true, data: terms });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.get('/terms/:id', async (req: PlatformRequest, res: express.Response) => {
  try {
    const term = await db.getTermByIdAsync(req.params.id, req.organization!.id);
    if (!term) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الفصل الدراسي غير موجود' });
    }
    res.json({ success: true, data: term });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/terms', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const { academicYearId, name, startDate, endDate, isCurrent } = req.body;
    if (!academicYearId || !name || !startDate || !endDate) {
      return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'جميع بيانات الفصل الدراسي مطلوبة' });
    }
    const yearExists = await db.getAcademicYearByIdAsync(academicYearId, req.organization!.id);
    if (!yearExists) {
      return res.status(400).json({ success: false, error: 'INVALID_YEAR', message: 'السنة الأكاديمية غير موجودة في المؤسسة' });
    }
    const term = await db.createTermAsync({
      organizationId: req.organization!.id,
      academicYearId,
      name: String(name).trim(),
      startDate,
      endDate,
      isCurrent: Boolean(isCurrent),
    });
    res.status(201).json({ success: true, data: term });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.put('/terms/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const existing = await db.getTermByIdAsync(req.params.id, req.organization!.id);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الفصل الدراسي غير موجود' });
    }
    const { name, startDate, endDate, isCurrent, academicYearId } = req.body;
    if (academicYearId && !(await db.getAcademicYearByIdAsync(academicYearId, req.organization!.id))) {
      return res.status(400).json({ success: false, error: 'INVALID_YEAR', message: 'السنة الأكاديمية غير صالحة' });
    }
    const updated = await db.updateTermAsync(req.params.id, req.organization!.id, {
      name: name ? String(name).trim() : undefined,
      startDate,
      endDate,
      isCurrent: isCurrent !== undefined ? Boolean(isCurrent) : undefined,
      academicYearId,
    });
    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/terms/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const success = await db.deleteTermAsync(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الفصل الدراسي غير موجود' });
    }
    res.json({ success: true, message: 'تم حذف الفصل الدراسي بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 3. Grade Levels
// ==========================================

academicRouter.get('/grades', async (req: PlatformRequest, res: express.Response) => {
  try {
    const grades = await db.getGradeLevelsAsync(req.organization!.id);
    res.json({ success: true, data: grades });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.get('/grades/:id', async (req: PlatformRequest, res: express.Response) => {
  try {
    const grade = await db.getGradeLevelByIdAsync(req.params.id, req.organization!.id);
    if (!grade) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'المرحلة الدراسية غير موجودة' });
    }
    res.json({ success: true, data: grade });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/grades', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const { name, sequenceOrder } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'NAME_REQUIRED', message: 'اسم المرحلة/الصف مطلوب' });
    const grade = await db.createGradeLevelAsync({
      organizationId: req.organization!.id,
      name: String(name).trim(),
      sequenceOrder: Number(sequenceOrder) || 1,
    });
    res.status(201).json({ success: true, data: grade });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.put('/grades/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const existing = await db.getGradeLevelByIdAsync(req.params.id, req.organization!.id);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'المرحلة الدراسية غير موجودة' });
    }
    const { name, sequenceOrder } = req.body;
    const updated = await db.updateGradeLevelAsync(req.params.id, req.organization!.id, {
      name: name ? String(name).trim() : undefined,
      sequenceOrder: sequenceOrder !== undefined ? Number(sequenceOrder) : undefined,
    });
    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/grades/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const success = await db.deleteGradeLevelAsync(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'المرحلة الدراسية غير موجودة' });
    }
    res.json({ success: true, message: 'تم حذف المرحلة الدراسية بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 4. Classrooms / Sections
// ==========================================

academicRouter.get('/classrooms', async (req: PlatformRequest, res: express.Response) => {
  try {
    const gradeLevelId = req.query.gradeLevelId as string | undefined;
    const classrooms = await db.getClassroomsAsync(req.organization!.id, gradeLevelId);
    res.json({ success: true, data: classrooms });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.get('/classrooms/:id', async (req: PlatformRequest, res: express.Response) => {
  try {
    const classroom = await db.getClassroomByIdAsync(req.params.id, req.organization!.id);
    if (!classroom) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الشعبة غير موجودة' });
    }
    res.json({ success: true, data: classroom });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/classrooms', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const { gradeLevelId, name, capacity } = req.body;
    if (!gradeLevelId || !name) {
      return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'الصف والمرحلة مطلوبة' });
    }

    if (!(await db.getGradeLevelByIdAsync(gradeLevelId, req.organization!.id))) {
      return res.status(400).json({ success: false, error: 'INVALID_GRADE_LEVEL', message: 'المرحلة الدراسية غير صالحة' });
    }

    const classroom = await db.createClassroomAsync({
      organizationId: req.organization!.id,
      gradeLevelId,
      name: String(name).trim(),
      capacity: capacity ? Number(capacity) : undefined,
    });
    res.status(201).json({ success: true, data: classroom });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.put('/classrooms/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const existing = await db.getClassroomByIdAsync(req.params.id, req.organization!.id);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الشعبة غير موجودة' });
    }
    const { name, gradeLevelId, capacity } = req.body;
    if (gradeLevelId && !(await db.getGradeLevelByIdAsync(gradeLevelId, req.organization!.id))) {
      return res.status(400).json({ success: false, error: 'INVALID_GRADE_LEVEL', message: 'المرحلة الدراسية غير صالحة' });
    }
    const updated = await db.updateClassroomAsync(req.params.id, req.organization!.id, {
      name: name ? String(name).trim() : undefined,
      gradeLevelId,
      capacity: capacity !== undefined ? Number(capacity) : undefined,
    });
    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/classrooms/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const success = await db.deleteClassroomAsync(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الشعبة غير موجودة' });
    }
    res.json({ success: true, message: 'تم حذف الشعبة بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 5. Subjects
// ==========================================

academicRouter.get('/subjects', async (req: PlatformRequest, res: express.Response) => {
  try {
    const subjects = await db.getSubjectsAsync(req.organization!.id);
    res.json({ success: true, data: subjects });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.get('/subjects/:id', async (req: PlatformRequest, res: express.Response) => {
  try {
    const subject = await db.getSubjectByIdAsync(req.params.id, req.organization!.id);
    if (!subject) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'المادة غير موجودة' });
    }
    res.json({ success: true, data: subject });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/subjects', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const { name, code, color, description } = req.body;
    if (!name || !code) {
      return res.status(400).json({ success: false, error: 'NAME_AND_CODE_REQUIRED', message: 'اسم المادة والرمز التعريفي مطلوبين' });
    }
    const subject = await db.createSubjectAsync({
      organizationId: req.organization!.id,
      name: String(name).trim(),
      code: String(code).trim().toUpperCase(),
      color: color || '#10b981',
      description: description ? String(description).trim() : undefined,
    });
    res.status(201).json({ success: true, data: subject });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.put('/subjects/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const existing = await db.getSubjectByIdAsync(req.params.id, req.organization!.id);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'المادة غير موجودة' });
    }
    const { name, code, color, description } = req.body;
    const updated = await db.updateSubjectAsync(req.params.id, req.organization!.id, {
      name: name ? String(name).trim() : undefined,
      code: code ? String(code).trim().toUpperCase() : undefined,
      color,
      description: description !== undefined ? String(description).trim() : undefined,
    });
    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/subjects/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const success = await db.deleteSubjectAsync(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'المادة غير موجودة' });
    }
    res.json({ success: true, message: 'تم حذف المادة بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 6. Teacher Assignments
// ==========================================

academicRouter.get('/teacher-assignments', (req: PlatformRequest, res: express.Response) => {
  try {
    const { role, id: userId } = req.user!;
    const orgId = req.organization!.id;
    const { teacherId, classroomId, courseId, academicYearId, subjectId } = req.query as Record<string, string>;

    let filterTeacher = teacherId;
    if (role === 'TEACHER') {
      filterTeacher = userId; // Teacher can only see their own assignments
    }

    const assignments = db.getTeacherAssignments(orgId, {
      teacherId: filterTeacher,
      classroomId,
      courseId,
      academicYearId,
      subjectId,
    });
    res.json({ success: true, data: assignments });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/teacher-assignments', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), (req: PlatformRequest, res: express.Response) => {
  try {
    const { teacherId, subjectId, classroomId, courseId, academicYearId, role, weeklyHours, status } = req.body;
    if (!teacherId || !subjectId || !classroomId) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_FIELDS',
        message: 'المعلم والمادة والشعبة الدراسية مطلوبة',
      });
    }

    const orgId = req.organization!.id;
    const teacher = db.getUserById(teacherId, orgId);
    if (!teacher || (teacher.role !== 'TEACHER' && teacher.role !== 'ORG_ADMIN')) {
      return res.status(400).json({ success: false, error: 'INVALID_TEACHER', message: 'المعلم المحدد غير موجود' });
    }
    if (!db.isSubjectInOrg(subjectId, orgId)) {
      return res.status(400).json({ success: false, error: 'INVALID_SUBJECT', message: 'المادة غير صالحة' });
    }
    if (!db.isClassroomInOrg(classroomId, orgId)) {
      return res.status(400).json({ success: false, error: 'INVALID_CLASSROOM', message: 'الشعبة غير صالحة' });
    }

    const assignment = db.createTeacherAssignment({
      organizationId: orgId,
      teacherId,
      subjectId,
      classroomId,
      courseId: courseId || undefined,
      academicYearId: academicYearId || undefined,
      role: role || 'PRIMARY_TEACHER',
      weeklyHours: weeklyHours ? Number(weeklyHours) : 4,
      status: status || 'ACTIVE',
    });

    res.status(201).json({ success: true, data: assignment });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.put('/teacher-assignments/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), (req: PlatformRequest, res: express.Response) => {
  try {
    const existing = db.getTeacherAssignmentById(req.params.id, req.organization!.id);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'تكليف المعلم غير موجود' });
    }
    const { teacherId, subjectId, classroomId, role, weeklyHours, status, courseId, academicYearId } = req.body;
    const orgId = req.organization!.id;

    if (teacherId) {
      const teacher = db.getUserById(teacherId, orgId);
      if (!teacher) return res.status(400).json({ success: false, error: 'INVALID_TEACHER', message: 'المعلم غير صالح' });
    }
    if (subjectId && !db.isSubjectInOrg(subjectId, orgId)) {
      return res.status(400).json({ success: false, error: 'INVALID_SUBJECT', message: 'المادة غير صالحة' });
    }
    if (classroomId && !db.isClassroomInOrg(classroomId, orgId)) {
      return res.status(400).json({ success: false, error: 'INVALID_CLASSROOM', message: 'الشعبة غير صالحة' });
    }

    const updated = db.updateTeacherAssignment(req.params.id, orgId, {
      teacherId,
      subjectId,
      classroomId,
      courseId,
      academicYearId,
      role,
      weeklyHours: weeklyHours !== undefined ? Number(weeklyHours) : undefined,
      status,
    });

    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/teacher-assignments/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), (req: PlatformRequest, res: express.Response) => {
  try {
    const success = db.deleteTeacherAssignment(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'التكليف غير موجود' });
    }
    res.json({ success: true, message: 'تم حذف تكليف المعلم بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 7. Student Enrollments
// ==========================================

academicRouter.get('/enrollments', async (req: PlatformRequest, res: express.Response) => {
  try {
    const { role, id: userId, classroomId: userClassroomId } = req.user!;
    const orgId = req.organization!.id;
    const { classroomId, studentId, academicYearId, status } = req.query as Record<string, string>;

    let filterStudent = studentId;
    let filterClassroom = classroomId;

    if (role === 'STUDENT') {
      filterStudent = userId; // Students can only view their own enrollment
    } else if (role === 'PARENT') {
      // Parents can only view enrollments of their linked children
      const links = db.getParentStudentLinks(orgId, { parentId: userId });
      const childIds = new Set(links.map((l) => l.studentId));
      if (studentId && !childIds.has(studentId)) {
        return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'لا تملك صلاحية الوصول لهذا الطالب' });
      }
    }

    const enrollments = await db.getStudentEnrollmentsAsync(orgId, {
      classroomId: filterClassroom,
      studentId: filterStudent,
      academicYearId,
      status: status as any,
    });

    res.json({ success: true, data: enrollments });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/enrollments', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const { studentId, classroomId, academicYearId, rollNumber, status } = req.body;
    if (!studentId || !classroomId || !academicYearId) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_FIELDS',
        message: 'الطالب والشعبة والسنة الأكاديمية مطلوبة لتسجيل الطالب',
      });
    }

    const orgId = req.organization!.id;
    const student = await db.getUserByIdAsync(studentId, orgId);
    if (!student || student.role !== 'STUDENT') {
      return res.status(400).json({ success: false, error: 'INVALID_STUDENT', message: 'الطالب غير موجود أو نوع الحساب غير صحيح' });
    }
    if (!db.isClassroomInOrg(classroomId, orgId)) {
      return res.status(400).json({ success: false, error: 'INVALID_CLASSROOM', message: 'الشعبة الدراسية غير صالحة' });
    }
      const yearExists = await db.getAcademicYearByIdAsync(academicYearId, orgId);
      if (!yearExists) {
        return res.status(400).json({ success: false, error: 'INVALID_YEAR', message: 'السنة الأكاديمية غير صالحة' });
    }

    // Check duplicate active enrollment for this student in the same year
    const existing = await db.getStudentEnrollmentsAsync(orgId, { studentId, academicYearId });
    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'DUPLICATE_ENROLLMENT',
        message: 'الطالب مسجل بالفعل في هذه السنة الأكاديمية',
        data: existing[0],
      });
    }

    const enrollment = await db.createStudentEnrollmentAsync({
      organizationId: orgId,
      studentId,
      classroomId,
      academicYearId,
      rollNumber: rollNumber ? String(rollNumber).trim() : undefined,
      status: status || 'ACTIVE',
    });

    res.status(201).json({ success: true, data: enrollment });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.put('/enrollments/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const existing = await db.getStudentEnrollmentByIdAsync(req.params.id, req.organization!.id);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'تسجيل الطالب غير موجود' });
    }

    const { classroomId, rollNumber, status } = req.body;
    const orgId = req.organization!.id;

    if (classroomId && !(await db.getClassroomByIdAsync(classroomId, orgId))) {
      return res.status(400).json({ success: false, error: 'INVALID_CLASSROOM', message: 'الشعبة غير صالحة' });
    }

    const updated = await db.updateStudentEnrollmentAsync(req.params.id, orgId, {
      classroomId,
      rollNumber: rollNumber !== undefined ? String(rollNumber).trim() : undefined,
      status,
    });

    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/enrollments/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const success = await db.deleteStudentEnrollmentAsync(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'تسجيل الطالب غير موجود' });
    }
    res.json({ success: true, message: 'تم إلغاء قيد الطالب بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 8. Parent-Student Links
// ==========================================

academicRouter.get('/parent-links', (req: PlatformRequest, res: express.Response) => {
  try {
    const { role, id: userId } = req.user!;
    const orgId = req.organization!.id;
    const { parentId, studentId } = req.query as Record<string, string>;

    let filterParent = parentId;
    if (role === 'PARENT') {
      filterParent = userId;
    }

    const links = db.getParentStudentLinks(orgId, { parentId: filterParent, studentId });
    res.json({ success: true, data: links });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.post('/parent-links', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), (req: PlatformRequest, res: express.Response) => {
  try {
    const { parentId, studentId, relationship, isEmergencyContact } = req.body;
    if (!parentId || !studentId) {
      return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'ولي الأمر والطالب مطلوبين' });
    }

    const orgId = req.organization!.id;
    const parent = db.getUserById(parentId, orgId);
    const student = db.getUserById(studentId, orgId);

    if (!parent || parent.role !== 'PARENT') {
      return res.status(400).json({ success: false, error: 'INVALID_PARENT', message: 'ولي الأمر غير موجود أو الدور غير صحيح' });
    }
    if (!student || student.role !== 'STUDENT') {
      return res.status(400).json({ success: false, error: 'INVALID_STUDENT', message: 'الطالب غير موجود أو الدور غير صحيح' });
    }

    const link = db.createParentStudentLink({
      organizationId: orgId,
      parentId,
      studentId,
      relationship: relationship || 'FATHER',
      isEmergencyContact: isEmergencyContact !== undefined ? Boolean(isEmergencyContact) : true,
    });

    res.status(201).json({ success: true, data: link });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

academicRouter.delete('/parent-links/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), (req: PlatformRequest, res: express.Response) => {
  try {
    const success = db.deleteParentStudentLink(req.params.id, req.organization!.id);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الرابط غير موجود' });
    }
    res.json({ success: true, message: 'تم فك ارتباط ولي الأمر بالطالب' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});
