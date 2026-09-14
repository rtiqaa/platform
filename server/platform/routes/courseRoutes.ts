import express from 'express';
import { db } from '../db.ts';
import type { PlatformRequest } from '../auth.ts';
import { requireAuth, requireRoles } from '../auth.ts';

export const courseRouter = express.Router();

courseRouter.use(requireAuth);

// GET /api/v1/courses (Filtered by role: teachers see assigned, students see classroom courses, admins see all)
courseRouter.get('/', async (req: PlatformRequest, res: express.Response) => {
  try {
    const { role, id: userId, classroomId } = req.user!;
    let courses = await db.getCoursesAsync(req.organization!.id);

    if (role === 'TEACHER') {
      courses = courses.filter((c) => c.teacherId === userId);
    } else if (role === 'STUDENT') {
      courses = classroomId ? courses.filter((c) => c.classroomId === classroomId) : [];
    }

    res.json({ success: true, data: courses });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// GET /api/v1/courses/:id
courseRouter.get('/:id', async (req: PlatformRequest, res: express.Response) => {
  try {
    const course = await db.getCourseByIdAsync(req.params.id, req.organization!.id);
    if (!course) return res.status(404).json({ success: false, error: 'COURSE_NOT_FOUND', message: 'المقرر غير موجود' });

    // Role-based access check
    if (req.user!.role === 'STUDENT' && course.classroomId !== req.user!.classroomId) {
      return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'لا تملك صلاحية الوصول لهذا المقرر' });
    }
    if (req.user!.role === 'TEACHER' && course.teacherId !== req.user!.id) {
      return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'هذا المقرر ليس مسنداً إليك' });
    }

    const [lessons, assignments, students, teacherAssignments] = await Promise.all([
      db.getLessonsByCourseAsync(course.id, req.organization!.id),
      db.getAssignmentsByCourseAsync(course.id, req.organization!.id),
      db.getCourseStudentsAsync(course.id, course.classroomId, req.organization!.id),
      db.getTeacherAssignmentsByCourseAsync(course.id, req.organization!.id),
    ]);
    const filteredLessons = req.user!.role === 'STUDENT' ? lessons.filter((l) => l.isPublished) : lessons;
    const teachers = [
      ...(course.teacherId
        ? [{ id: course.teacherId, fullName: course.teacherName, email: undefined, role: 'PRIMARY_TEACHER' }]
        : []),
      ...teacherAssignments.map((assignment) => ({
        id: assignment.teacherId,
        fullName: assignment.teacherName,
        email: assignment.teacherEmail,
        role: assignment.role,
      })),
    ].filter((teacher, index, all) => all.findIndex((item) => item.id === teacher.id) === index);

    res.json({
      success: true,
      data: {
        ...course,
        lessons: filteredLessons,
        assignments,
        teacherAssignments,
        teachers,
        studentsCount: students.length,
        students: students.map((s) => ({ id: s.id, fullName: s.fullName, studentIdNumber: s.studentIdNumber, email: s.email })),
      },
    });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/courses (Admins & Teachers can create)
courseRouter.post('/', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN', 'TEACHER']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const { subjectId, termId, classroomId, title, description, teacherId } = req.body;
    if (!subjectId || !termId || !classroomId || !title) {
      return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'المادة والفصل والشعبة وعنوان المقرر مطلوبة' });
    }

    const orgId = req.organization!.id;

    // Validate foreign keys in same tenant
    if (!(await db.getSubjectByIdAsync(subjectId, orgId))) {
      return res.status(400).json({ success: false, error: 'INVALID_SUBJECT', message: 'المادة غير صالحة' });
    }
    if (!(await db.getTermByIdAsync(termId, orgId))) {
      return res.status(400).json({ success: false, error: 'INVALID_TERM', message: 'الفصل الدراسي غير صالح' });
    }
    if (!(await db.getClassroomByIdAsync(classroomId, orgId))) {
      return res.status(400).json({ success: false, error: 'INVALID_CLASSROOM', message: 'الشعبة الدراسية غير صالحة' });
    }

    let assignedTeacherId = req.user!.id;
    if (req.user!.role === 'ORG_ADMIN' || req.user!.role === 'SUPER_ADMIN') {
      if (teacherId) {
        const t = await db.getUserByIdAsync(teacherId, orgId);
        if (!t || (t.role !== 'TEACHER' && t.role !== 'ORG_ADMIN')) {
          return res.status(400).json({ success: false, error: 'INVALID_TEACHER', message: 'المعلم المحدد غير موجود' });
        }
        assignedTeacherId = t.id;
      }
    }

    const course = await db.createCourseAsync({
      organizationId: orgId,
      subjectId,
      termId,
      classroomId,
      title: String(title).trim(),
      description: description ? String(description).trim() : undefined,
      teacherId: assignedTeacherId,
    });

    res.json({ success: true, data: course });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// PUT /api/v1/courses/:id (Admins or assigned teacher)
courseRouter.put('/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN', 'TEACHER']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const orgId = req.organization!.id;
    const course = await db.getCourseByIdAsync(req.params.id, orgId);
    if (!course) {
      return res.status(404).json({ success: false, error: 'COURSE_NOT_FOUND', message: 'المقرر غير موجود' });
    }

    if (req.user!.role === 'TEACHER' && course.teacherId !== req.user!.id) {
      return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'لا تملك صلاحية تعديل هذا المقرر' });
    }

    const { title, description, subjectId, classroomId, termId, teacherId } = req.body;

    if (subjectId && !(await db.getSubjectByIdAsync(subjectId, orgId))) {
      return res.status(400).json({ success: false, error: 'INVALID_SUBJECT', message: 'المادة غير صالحة' });
    }
    if (termId && !(await db.getTermByIdAsync(termId, orgId))) {
      return res.status(400).json({ success: false, error: 'INVALID_TERM', message: 'الفصل الدراسي غير صالح' });
    }
    if (classroomId && !(await db.getClassroomByIdAsync(classroomId, orgId))) {
      return res.status(400).json({ success: false, error: 'INVALID_CLASSROOM', message: 'الشعبة الدراسية غير صالحة' });
    }

    let finalTeacherId = course.teacherId;
    if ((req.user!.role === 'ORG_ADMIN' || req.user!.role === 'SUPER_ADMIN') && teacherId) {
      const t = await db.getUserByIdAsync(teacherId, orgId);
      if (!t) {
        return res.status(400).json({ success: false, error: 'INVALID_TEACHER', message: 'المعلم المحدد غير صالح' });
      }
      finalTeacherId = t.id;
    }

    const updated = await db.updateCourseAsync(req.params.id, orgId, {
      title: title ? String(title).trim() : undefined,
      description: description !== undefined ? String(description).trim() : undefined,
      subjectId,
      classroomId,
      termId,
      teacherId: finalTeacherId,
    });

    res.json({ success: true, data: updated });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// DELETE /api/v1/courses/:id (Admins only)
courseRouter.delete('/:id', requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']), async (req: PlatformRequest, res: express.Response) => {
  try {
    const orgId = req.organization!.id;
    const course = await db.getCourseByIdAsync(req.params.id, orgId);
    if (!course) {
      return res.status(404).json({ success: false, error: 'COURSE_NOT_FOUND', message: 'المقرر غير موجود' });
    }

    const success = await db.deleteCourseAsync(req.params.id, orgId);
    if (!success) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'فشل حذف المقرر' });
    }

    res.json({ success: true, message: 'تم حذف المقرر بنجاح' });
  } catch {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

