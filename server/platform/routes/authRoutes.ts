import express from 'express';
import { db } from '../db.ts';
import type { PlatformRequest } from '../auth.ts';
import { generateToken, requireAuth, requireRoles } from '../auth.ts';
import {
  createRateLimiter,
  hashPassword,
  verifyPassword,
  generateInviteCode,
  generateOtp,
  hashOtp,
  verifyOtp,
  generateSecureToken,
  validatePasswordStrength,
  isValidEmail,
  sanitizeString,
} from '../security.ts';
import { getActiveSmsProvider, normalizePhoneNumber } from '../smsService.ts';
import {
  buildGoogleAuthUrl,
  exchangeGoogleCodeForProfile,
  verifyGoogleIdToken,
  generateOAuthState,
  parseOAuthState,
  getGoogleOAuthCredentials,
} from '../googleAuth.ts';
import { emailService } from '../emailService.ts';
import type { UserRole, AuthProviderType, User } from '../types.ts';

export const authRouter = express.Router();

// Rate limiters for security
const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 30,
  message: 'تم تجاوز عدد محاولات تسجيل الدخول المسموح بها، يرجى المحاولة بعد قليل.',
});

const otpLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  maxRequests: 10,
  message: 'تم تجاوز الحد المسموح لطلب رموز التحقق، يرجى الانتظار 10 دقائق.',
});

const registerLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  maxRequests: 20,
  message: 'تم تجاوز عدد عمليات التسجيل المسموح بها من هذا العنوان، يرجى المحاولة لاحقاً.',
});

const forgotPasswordLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  maxRequests: 10,
  message: 'تم تجاوز الحد الأقصى لطلب استعادة كلمة المرور، يرجى المحاولة لاحقاً.',
});

const inviteLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  maxRequests: 50,
  message: 'تم تجاوز الحد الأقصى لإرسال الدعوات، يرجى المحاولة لاحقاً.',
});

const acceptInviteLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 15,
  message: 'تم تجاوز عدد محاولات قبول الدعوة، يرجى المحاولة بعد قليل.',
});

// Helper to sanitize safe user object for response
function formatUserResponse(user: User) {
  const memberships = db.getMembershipsByUserId(user.id);
  return {
    id: user.id,
    organizationId: user.organizationId,
    email: user.email,
    phone: user.phone,
    fullName: user.fullName,
    role: user.role,
    avatarUrl: user.avatarUrl,
    emailVerified: user.emailVerified ?? false,
    phoneVerified: user.phoneVerified ?? false,
    authProviders: user.authProviders || ['email'],
    googleId: user.googleId,
    classroomId: user.classroomId,
    studentIdNumber: user.studentIdNumber,
    teacherSpecialization: user.teacherSpecialization,
    memberships,
    createdAt: user.createdAt,
  };
}

async function formatUserResponseAsync(user: User) {
  const memberships = await db.getMembershipsByUserIdAsync(user.id);
  return {
    id: user.id,
    organizationId: user.organizationId,
    email: user.email,
    phone: user.phone,
    fullName: user.fullName,
    role: user.role,
    avatarUrl: user.avatarUrl,
    emailVerified: user.emailVerified ?? false,
    phoneVerified: user.phoneVerified ?? false,
    authProviders: user.authProviders || ['email'],
    googleId: user.googleId,
    classroomId: user.classroomId,
    studentIdNumber: user.studentIdNumber,
    teacherSpecialization: user.teacherSpecialization,
    memberships,
    createdAt: user.createdAt,
  };
}

/**
 * Unified Super Admin Email Verifier
 * Reads exclusively from SUPER_ADMIN_EMAILS environment variable (comma-separated).
 * Performs case-insensitive matching and trimming. Never assumes any fallback or hardcoded email.
 */
export function isSuperAdminEmail(email?: string): boolean {
  if (!email || typeof email !== 'string') return false;
  const configuredAdmins = (process.env.SUPER_ADMIN_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  if (configuredAdmins.length === 0) return false;
  return configuredAdmins.includes(email.trim().toLowerCase());
}

// Helper to generate the token and figure out the initial context for login
function generateLoginContext(user: User) {
  const memberships = db.getMembershipsByUserId(user.id);
  const isSuperAdmin = user.role === 'SUPER_ADMIN';
  const requiresOnboarding = !isSuperAdmin && memberships.length === 0;

  let token: string;
  let activeMembership = undefined;
  let org = undefined;

  if (isSuperAdmin) {
    token = generateToken(user, undefined, 'SUPER_ADMIN', undefined, 'PERSONAL');
  } else if (memberships.length > 0) {
    activeMembership = memberships.find((m) => m.isDefault && m.status === 'ACTIVE') || memberships.find((m) => m.status === 'ACTIVE') || memberships[0];
    token = generateToken(
      user,
      activeMembership.organizationId,
      activeMembership.role,
      activeMembership.id,
      'ORGANIZATION'
    );
    org = db.getOrganizationById(activeMembership.organizationId);
  } else {
    token = generateToken(user, undefined, user.role, undefined, 'PERSONAL');
  }

  return { token, activeMembership, org, requiresOnboarding };
}

async function generateLoginContextAsync(user: User) {
  const memberships = await db.getMembershipsByUserIdAsync(user.id);
  const isSuperAdmin = user.role === 'SUPER_ADMIN';
  const requiresOnboarding = !isSuperAdmin && memberships.length === 0;

  if (isSuperAdmin) {
    return {
      token: generateToken(user, undefined, 'SUPER_ADMIN', undefined, 'PERSONAL'),
      activeMembership: undefined,
      org: undefined,
      requiresOnboarding,
    };
  }

  const activeMembership = memberships.find((m) => m.isDefault && m.status === 'ACTIVE') || memberships.find((m) => m.status === 'ACTIVE') || memberships[0];
  if (!activeMembership) {
    return {
      token: generateToken(user, undefined, user.role, undefined, 'PERSONAL'),
      activeMembership: undefined,
      org: undefined,
      requiresOnboarding,
    };
  }

  return {
    token: generateToken(user, activeMembership.organizationId, activeMembership.role, activeMembership.id, 'ORGANIZATION'),
    activeMembership,
    org: await db.getOrganizationByIdAsync(activeMembership.organizationId),
    requiresOnboarding,
  };
}

// ====================================================================
// 1. STANDARD CREDENTIALS AUTH (EMAIL / PHONE & PASSWORD)
// ====================================================================

// POST /api/v1/auth/login (Support Login via Email OR Phone)
authRouter.post('/login', loginLimiter, async (req: PlatformRequest, res: express.Response) => {
  try {
    const { email, identifier, phone, password, tenantSlug } = req.body;
    const loginIdentifier = sanitizeString(identifier || email || phone);

    if (!loginIdentifier) {
      return res.status(400).json({
        success: false,
        error: 'EMAIL_REQUIRED',
        message: 'البريد الإلكتروني أو رقم الهاتف مطلوب لتسجيل الدخول',
      });
    }

    let orgId: string | undefined = undefined;
    if (tenantSlug) {
      const org = await db.getOrganizationBySlugAsync(sanitizeString(tenantSlug));
      if (org) orgId = org.id;
    }

    let user: User | undefined = undefined;

    // Check if identifier is email or phone
    if (isValidEmail(loginIdentifier)) {
      user = await db.findUserByEmailAsync(loginIdentifier.toLowerCase(), orgId);
    } else {
      const phoneNorm = normalizePhoneNumber(loginIdentifier);
      if (phoneNorm.isValid) {
        user = await db.findUserByPhoneAsync(phoneNorm.e164, orgId);
      } else {
        // Fallback search by email
        user = await db.findUserByEmailAsync(loginIdentifier.toLowerCase(), orgId);
      }
    }

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'بيانات تسجيل الدخول غير صحيحة أو الحساب غير مفعّل',
      });
    }

    // Verify Password if provided and user has a passwordHash
    if (password && user.passwordHash) {
      const isCorrect = verifyPassword(password, user.passwordHash);
      if (!isCorrect) {
        return res.status(401).json({
          success: false,
          error: 'INVALID_CREDENTIALS',
          message: 'كلمة المرور غير صحيحة',
        });
      }
    }

    // Auto-promote user to SUPER_ADMIN if email is configured in SUPER_ADMIN_EMAILS
    if (isSuperAdminEmail(user.email) && user.role !== 'SUPER_ADMIN') {
      const updatedUser = await db.updateUserAsync(user.id, user.organizationId!, { role: 'SUPER_ADMIN' });
      if (updatedUser) {
        user = updatedUser;
      }
    }

    const { token, org, requiresOnboarding } = await generateLoginContextAsync(user);

    db.logAction(org?.id || 'platform', user.id, user.email, 'LOGIN', 'User', user.id, {}, req.ip);

    return res.json({
      success: true,
      token,
      user: await formatUserResponseAsync(user),
      organization: org,
      requiresOnboarding,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/register (Standard User Registration)
authRouter.post('/register', registerLimiter, async (req: PlatformRequest, res: express.Response) => {
  try {
    const { fullName, email, phone, password, role = 'STUDENT', tenantSlug } = req.body;

    if (!fullName || (!email && !phone)) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_FIELDS',
        message: 'الاسم الكامل والبريد الإلكتروني أو رقم الهاتف مطلوبان للتسجيل',
      });
    }

    const cleanFullName = sanitizeString(fullName);
    if (cleanFullName.length < 2) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_NAME',
        message: 'يرجى إدخال اسم صحيح مكون من حرفين على الأقل',
      });
    }

    let cleanEmail = '';
    if (email) {
      cleanEmail = sanitizeString(email).toLowerCase();
      if (!isValidEmail(cleanEmail)) {
        return res.status(400).json({
          success: false,
          error: 'INVALID_EMAIL',
          message: 'صيغة البريد الإلكتروني غير صحيحة',
        });
      }
    }

    let cleanPhone = '';
    if (phone) {
      const phoneNorm = normalizePhoneNumber(phone);
      if (!phoneNorm.isValid) {
        return res.status(400).json({
          success: false,
          error: 'INVALID_PHONE',
          message: phoneNorm.error || 'صيغة رقم الهاتف غير صالحة',
        });
      }
      cleanPhone = phoneNorm.e164;
    }

    // Resolve target Organization
    const targetSlug = sanitizeString(tenantSlug) || 'horizon';
    let org = await db.getOrganizationBySlugAsync(targetSlug);
    if (!org) {
      org = await db.getOrganizationBySlugAsync('horizon');
    }
    if (!org) {
      return res.status(503).json({ success: false, error: 'ORGANIZATION_STORE_UNAVAILABLE' });
    }
    const orgId = org ? org.id : 'org_horizon_001';

    // Check duplicate email
    if (cleanEmail) {
      const existingEmail = await db.findUserByEmailAsync(cleanEmail, orgId);
      if (existingEmail) {
        return res.status(400).json({
          success: false,
          error: 'EMAIL_IN_USE',
          message: 'البريد الإلكتروني مستخدم بالفعل، يرجى تسجيل الدخول أو استعادة كلمة المرور',
        });
      }
    }

    // Check duplicate phone
    if (cleanPhone) {
      const existingPhone = await db.findUserByPhoneAsync(cleanPhone, orgId);
      if (existingPhone) {
        return res.status(400).json({
          success: false,
          error: 'PHONE_IN_USE',
          message: 'رقم الهاتف مستخدم بالفعل بحساب آخر',
        });
      }
    }

    // Validate password if provided
    let passwordHash: string | undefined = undefined;
    if (password) {
      const pStrength = validatePasswordStrength(password);
      if (!pStrength.isValid) {
        return res.status(400).json({
          success: false,
          error: 'WEAK_PASSWORD',
          message: pStrength.message,
        });
      }
      passwordHash = hashPassword(password);
    }

    const providers: AuthProviderType[] = [];
    if (cleanEmail && password) providers.push('email');
    if (cleanPhone) providers.push('phone');

    const validRoles: UserRole[] = ['STUDENT', 'TEACHER', 'PARENT', 'ORG_ADMIN'];
    const chosenRole: UserRole = validRoles.includes(role as UserRole) ? (role as UserRole) : 'STUDENT';

    const newUser = await db.createUserAsync({
      organizationId: orgId,
      email: cleanEmail || `user_${Date.now()}@rtiqa.local`,
      phone: cleanPhone || undefined,
      fullName: cleanFullName,
      passwordHash,
      role: chosenRole,
      emailVerified: false,
      phoneVerified: false,
      authProviders: providers.length > 0 ? providers : ['email'],
      isActive: true,
    });

    const { token, org: generatedOrg, requiresOnboarding } = await generateLoginContextAsync(newUser);

    // Create verification token if email provided
    let verificationSent = false;
    if (cleanEmail) {
      const rawToken = generateSecureToken(24);
      const tokenHash = hashOtp(rawToken);
      db.createEmailVerificationToken(newUser.id, cleanEmail, tokenHash);
      verificationSent = true;
    }

    db.logAction(orgId, newUser.id, newUser.email, 'REGISTER', 'User', newUser.id, { role: chosenRole }, req.ip);

    return res.status(201).json({
      success: true,
      token,
      user: await formatUserResponseAsync(newUser),
      organization: generatedOrg || org,
      requiresOnboarding,
      verificationSent,
      message: 'تم إنشاء الحساب بنجاح',
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ====================================================================
// 2. PHONE NUMBER & OTP AUTHENTICATION FLOW
// ====================================================================

// POST /api/v1/auth/phone/otp/send (Send 6-digit OTP to Phone)
authRouter.post('/phone/otp/send', otpLimiter, async (req: express.Request, res: express.Response) => {
  try {
    const { phone, purpose = 'login' } = req.body;

    const phoneNorm = normalizePhoneNumber(phone);
    if (!phoneNorm.isValid) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_PHONE',
        message: phoneNorm.error || 'يرجى إدخال رقم هاتف دولي صالح',
      });
    }

    // Check cooldown for active OTP
    const existingOtp = db.getLatestActivePhoneOtp(phoneNorm.e164);
    if (existingOtp) {
      const createdTime = new Date(existingOtp.createdAt).getTime();
      const secondsSince = (Date.now() - createdTime) / 1000;
      if (secondsSince < 60) {
        const remaining = Math.ceil(60 - secondsSince);
        return res.status(429).json({
          success: false,
          error: 'OTP_COOLDOWN',
          message: `يرجى الانتظار ${remaining} ثانية قبل طلب رمز جديد`,
          retryAfterSeconds: remaining,
        });
      }
    }

    const otp = generateOtp(6);
    const otpHash = hashOtp(otp);

    // Optional user matching
    const existingUser = await db.findUserByPhoneAsync(phoneNorm.e164);
    db.createPhoneOtp(phoneNorm.e164, otpHash, existingUser?.id, 10);

    const smsProvider = getActiveSmsProvider();
    const smsResult = await smsProvider.sendOtp(phoneNorm.e164, otp, purpose);

    return res.json({
      success: true,
      phone: phoneNorm.e164,
      provider: smsResult.provider,
      isSimulated: smsResult.isSimulated ?? false,
      expiresInSeconds: 600,
      cooldownSeconds: 60,
      message: 'تم إرسال رمز التحقق بنجاح إلى هاتفك',
      // In non-production/test environments with simulated SMS, provide code for developer testing
      ...(process.env.NODE_ENV !== 'production' ? { devOtpCode: otp } : {}),
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/phone/otp/verify (Verify OTP & Login or Register)
authRouter.post('/phone/otp/verify', loginLimiter, async (req: express.Request, res: express.Response) => {
  try {
    const { phone, code, fullName, tenantSlug } = req.body;

    const phoneNorm = normalizePhoneNumber(phone);
    if (!phoneNorm.isValid) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_PHONE',
        message: phoneNorm.error || 'رقم الهاتف غير صالح',
      });
    }

    if (!code || typeof code !== 'string' || code.trim().length < 4) {
      return res.status(400).json({
        success: false,
        error: 'CODE_REQUIRED',
        message: 'رمز التحقق مطلوب',
      });
    }

    const activeOtp = db.getLatestActivePhoneOtp(phoneNorm.e164);
    if (!activeOtp) {
      return res.status(400).json({
        success: false,
        error: 'OTP_EXPIRED_OR_NOT_FOUND',
        message: 'رمز التحقق منتهي الصلاحية أو غير موجود، يرجى طلب رمز جديد',
      });
    }

    const isMatch = verifyOtp(code.trim(), activeOtp.otpHash);
    if (!isMatch) {
      const attempts = db.incrementPhoneOtpAttempts(activeOtp.id);
      const remainingAttempts = Math.max(0, activeOtp.maxAttempts - attempts);

      if (remainingAttempts === 0) {
        return res.status(400).json({
          success: false,
          error: 'OTP_MAX_ATTEMPTS_EXCEEDED',
          message: 'تم تجاوز عدد المحاولات الخاطئة. تم إلغاء الرمز، يرجى طلب رمز جديد.',
        });
      }

      return res.status(400).json({
        success: false,
        error: 'INVALID_OTP',
        message: `رمز التحقق غير صحيح. يتبقى لديك ${remainingAttempts} محاولات.`,
        remainingAttempts,
      });
    }

    // OTP Verified! Mark used
    db.markPhoneOtpUsed(activeOtp.id);

    // Find or create user
    let user = await db.findUserByPhoneAsync(phoneNorm.e164);

    if (!user) {
      // Resolve organization
      const targetSlug = sanitizeString(tenantSlug) || 'horizon';
      const org = await db.getOrganizationBySlugAsync(targetSlug);
      if (!org) {
        return res.status(503).json({ success: false, error: 'ORGANIZATION_STORE_UNAVAILABLE' });
      }
      const orgId = org ? org.id : 'org_horizon_001';

      const userName = fullName ? sanitizeString(fullName) : `مستخدم ${phoneNorm.e164.slice(-4)}`;

      user = await db.createUserAsync({
        organizationId: orgId,
        email: `phone_${phoneNorm.e164.replace(/[^0-9]/g, '')}@rtiqa.local`,
        phone: phoneNorm.e164,
        fullName: userName,
        role: 'STUDENT',
        phoneVerified: true,
        authProviders: ['phone'],
        isActive: true,
      });
    } else {
      // Update phoneVerified flag and link provider if not present
      if (user.organizationId) {
        user = (await db.updateUserAsync(user.id, user.organizationId, {
          phone: phoneNorm.e164,
          phoneVerified: true,
          authProviders: Array.from(new Set([...(user.authProviders || []), 'phone'] as AuthProviderType[])),
        })) || user;
      }
    }

    const { token, org, requiresOnboarding } = await generateLoginContextAsync(user);

    db.logAction(org?.id || 'platform', user.id, user.email, 'LOGIN_PHONE_OTP', 'User', user.id, { phone: phoneNorm.e164 }, req.ip);

    return res.json({
      success: true,
      token,
      user: await formatUserResponseAsync(user),
      organization: org,
      requiresOnboarding,
      message: 'تم التحقق وتسجيل الدخول بنجاح',
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ====================================================================
// 3. GOOGLE SIGN-IN & OAUTH FLOW
// ====================================================================

// GET /api/v1/auth/google/url (Get Google OAuth Authorization URL)
authRouter.get('/google/url', (req: express.Request, res: express.Response) => {
  try {
    const tenantSlug = req.query.tenantSlug as string | undefined;
    const state = generateOAuthState(tenantSlug ? sanitizeString(tenantSlug) : undefined);

    // Compute redirect URI based on request host or APP_URL
    const host = req.get('host') || 'localhost:3000';
    const protocol = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
    const origin = process.env.APP_URL || `${protocol}://${host}`;
    const redirectUri = `${origin}/api/v1/auth/google/callback`;

    const { url, clientId } = buildGoogleAuthUrl(redirectUri, state);
    const { isConfigured } = getGoogleOAuthCredentials();

    return res.json({
      success: true,
      url,
      clientId,
      state,
      isConfigured,
      redirectUri,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// GET & POST /api/v1/auth/google/callback (Handle Google OAuth Callback)
const handleGoogleCallback = async (req: express.Request, res: express.Response) => {
  try {
    const code = (req.query.code || req.body?.code) as string;
    const state = (req.query.state || req.body?.state) as string;
    const isPopup = req.query.popup === 'true' || req.headers.accept?.includes('text/html');

    if (!code) {
      if (isPopup) {
        return res.send(`
          <html><body><script>
            window.opener && window.opener.postMessage({ type: 'GOOGLE_AUTH_ERROR', error: 'MISSING_CODE' }, '*');
            window.close();
          </script></body></html>
        `);
      }
      return res.status(400).json({ success: false, error: 'CODE_REQUIRED', message: 'رمز تفويض Google مطلوب' });
    }

    const stateParsed = parseOAuthState(state);
    const tenantSlug = stateParsed.tenantSlug;

    const host = req.get('host') || 'localhost:3000';
    const protocol = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
    const origin = process.env.APP_URL || `${protocol}://${host}`;
    const redirectUri = `${origin}/api/v1/auth/google/callback`;

    const exchange = await exchangeGoogleCodeForProfile(code, redirectUri);
    if (!exchange.success || !exchange.profile) {
      if (isPopup) {
        return res.send(`
          <html><body><script>
            window.opener && window.opener.postMessage({ type: 'GOOGLE_AUTH_ERROR', error: ${JSON.stringify(exchange.error)} }, '*');
            window.close();
          </script></body></html>
        `);
      }
      return res.status(400).json({ success: false, error: 'GOOGLE_AUTH_FAILED', message: exchange.error });
    }

    const { profile } = exchange;
    const emailNorm = profile.email.toLowerCase().trim();

    // 1. Look up existing user by googleId or email
    let user = await db.findUserByGoogleIdAsync(profile.sub) || await db.findUserByEmailAsync(emailNorm);

    if (user) {
      // Link Google provider safely
      const providerUpdates: Partial<User> = {
        authProviders: Array.from(new Set([...(user.authProviders || []), 'google'] as AuthProviderType[])),
        googleId: profile.sub,
        email: emailNorm,
        ...(profile.picture && !user.avatarUrl ? { avatarUrl: profile.picture } : {}),
        ...(profile.email_verified && !user.emailVerified ? { emailVerified: true } : {}),
      };
      user = (await db.updateUserAsync(user.id, user.organizationId!, providerUpdates)) || user;

      // Auto-promote existing user if email is verified by Google and matches SUPER_ADMIN_EMAILS
      if (profile.email_verified && isSuperAdminEmail(emailNorm) && user.role !== 'SUPER_ADMIN') {
        const updatedUser = await db.updateUserAsync(user.id, user.organizationId!, { role: 'SUPER_ADMIN' });
        if (updatedUser) {
          user = updatedUser;
        }
      }

      user = (await db.getUserByIdAsync(user.id, user.organizationId))!;
    } else {
      // 2. Check for pending invitations for this email
      const pendingInvitations = await db.getPendingInvitationsByEmailAsync(emailNorm);

      if (pendingInvitations.length > 0) {
        // Automatically claim the valid invitation
        const invitation = pendingInvitations[0];
        const assignedRole: UserRole =
          profile.email_verified && isSuperAdminEmail(emailNorm) ? 'SUPER_ADMIN' : invitation.role;

        user = await db.createUserAsync({
          organizationId: invitation.organizationId,
          email: emailNorm,
          fullName: invitation.fullName || profile.name || emailNorm.split('@')[0],
          avatarUrl: profile.picture,
          role: assignedRole,
          classroomId: invitation.classroomId,
          teacherSpecialization: invitation.teacherSpecialization,
          studentIdNumber: invitation.studentIdNumber || (invitation.role === 'STUDENT' ? `STD-${Date.now().toString().slice(-5)}` : undefined),
          emailVerified: profile.email_verified,
          phoneVerified: false,
          authProviders: ['google'],
          googleId: profile.sub,
          isActive: true,
        });

        await db.markInvitationUsedAsync(invitation.id, invitation.organizationId);
      } else {
        // 3. New users without an organization cannot be persisted by the production schema.
        // If email is verified by Google and configured in SUPER_ADMIN_EMAILS, assign SUPER_ADMIN; otherwise PENDING
        const assignedRole: UserRole =
          profile.email_verified && isSuperAdminEmail(emailNorm) ? 'SUPER_ADMIN' : 'PENDING';

        if (process.env.NODE_ENV === 'production') {
          return res.status(409).json({ success: false, error: 'ORGANIZATION_REQUIRED', message: 'انضم إلى مؤسسة أو أنشئ مؤسسة قبل إكمال تسجيل Google.' });
        }
        user = await db.createUserAsync({
          email: emailNorm,
          fullName: profile.name || emailNorm.split('@')[0],
          avatarUrl: profile.picture,
          role: assignedRole,
          emailVerified: profile.email_verified,
          phoneVerified: false,
          authProviders: ['google'],
          googleId: profile.sub,
          isActive: true,
        });
      }
    }

    const { token, org, requiresOnboarding: isNewUserPendingOnboarding } = await generateLoginContextAsync(user);

    const logOrgId = org?.id || 'platform';
    db.logAction(logOrgId, user.id, user.email, 'LOGIN_GOOGLE', 'User', user.id, {
      googleSub: profile.sub,
      isPendingOnboarding: isNewUserPendingOnboarding,
    }, req.ip);

    if (isPopup) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Authentication Complete</title></head>
        <body>
          <script>
            const authPayload = {
              type: 'GOOGLE_AUTH_SUCCESS',
              token: ${JSON.stringify(token)},
              user: ${JSON.stringify(await formatUserResponseAsync(user))},
              organization: ${JSON.stringify(org || null)},
              status: ${JSON.stringify(isNewUserPendingOnboarding ? 'PENDING_ONBOARDING' : 'AUTHENTICATED')},
              requiresOnboarding: ${isNewUserPendingOnboarding}
            };
            if (window.opener) {
              window.opener.postMessage(authPayload, '*');
              window.close();
            } else {
              window.location.href = ${isNewUserPendingOnboarding ? "'/platform/onboarding'" : "'/platform/dashboard'"};
            }
          </script>
          <div style="font-family: sans-serif; text-align: center; padding: 40px;">
            <h2>تم تسجيل الدخول بنجاح</h2>
            <p>${isNewUserPendingOnboarding ? 'جارٍ تحويلك لإكمال الانضمام أو تسجيل مدرسة...' : 'جارٍ تحويلك إلى لوحة التحكم...'}</p>
          </div>
        </body>
        </html>
      `);
    }

    return res.json({
      success: true,
      token,
      user: await formatUserResponseAsync(user),
      organization: org || null,
      status: isNewUserPendingOnboarding ? 'PENDING_ONBOARDING' : 'AUTHENTICATED',
      requiresOnboarding: isNewUserPendingOnboarding,
      message: isNewUserPendingOnboarding
        ? 'تم التحقق من حساب Google بنجاح. يرجى اختيار الانضمام لمدرسة أو تسجيل مدرسة جديدة.'
        : 'تم تسجيل الدخول بواسطة Google بنجاح',
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
};

authRouter.get('/google/callback', handleGoogleCallback);
authRouter.post('/google/callback', handleGoogleCallback);

// POST /api/v1/auth/google/verify-credential (Google One Tap / Google Button Credential)
authRouter.post('/google/verify-credential', loginLimiter, async (req: express.Request, res: express.Response) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ success: false, error: 'CREDENTIAL_REQUIRED', message: 'رمز Google Credential مطلوب' });
    }

    const verify = await verifyGoogleIdToken(credential);
    if (!verify.success || !verify.profile) {
      return res.status(401).json({
        success: false,
        error: 'INVALID_GOOGLE_CREDENTIAL',
        message: verify.error || 'فشل التحقق من هوية Google',
      });
    }

    const { profile } = verify;
    const emailNorm = profile.email.toLowerCase().trim();

    let user = await db.findUserByGoogleIdAsync(profile.sub) || await db.findUserByEmailAsync(emailNorm);

    if (user) {
      const providerUpdates: Partial<User> = {
        authProviders: Array.from(new Set([...(user.authProviders || []), 'google'] as AuthProviderType[])),
        googleId: profile.sub,
        email: emailNorm,
        ...(profile.picture && !user.avatarUrl ? { avatarUrl: profile.picture } : {}),
        ...(profile.email_verified && !user.emailVerified ? { emailVerified: true } : {}),
      };
      user = (await db.updateUserAsync(user.id, user.organizationId!, providerUpdates)) || user;

      // Auto-promote existing user if email is verified by Google and matches SUPER_ADMIN_EMAILS
      if (profile.email_verified && isSuperAdminEmail(emailNorm) && user.role !== 'SUPER_ADMIN') {
        const updatedUser = await db.updateUserAsync(user.id, user.organizationId!, { role: 'SUPER_ADMIN' });
        if (updatedUser) {
          user = updatedUser;
        }
      }

      user = (await db.getUserByIdAsync(user.id, user.organizationId))!;
    } else {
      const pendingInvitations = await db.getPendingInvitationsByEmailAsync(emailNorm);

      if (pendingInvitations.length > 0) {
        const invitation = pendingInvitations[0];
        const assignedRole: UserRole =
          profile.email_verified && isSuperAdminEmail(emailNorm) ? 'SUPER_ADMIN' : invitation.role;

        user = await db.createUserAsync({
          organizationId: invitation.organizationId,
          email: emailNorm,
          fullName: invitation.fullName || profile.name || emailNorm.split('@')[0],
          avatarUrl: profile.picture,
          role: assignedRole,
          classroomId: invitation.classroomId,
          teacherSpecialization: invitation.teacherSpecialization,
          studentIdNumber: invitation.studentIdNumber || (invitation.role === 'STUDENT' ? `STD-${Date.now().toString().slice(-5)}` : undefined),
          emailVerified: profile.email_verified,
          phoneVerified: false,
          authProviders: ['google'],
          googleId: profile.sub,
          isActive: true,
        });

        await db.markInvitationUsedAsync(invitation.id, invitation.organizationId);
      } else {
        // If email is verified by Google and configured in SUPER_ADMIN_EMAILS, assign SUPER_ADMIN; otherwise PENDING
        const assignedRole: UserRole =
          profile.email_verified && isSuperAdminEmail(emailNorm) ? 'SUPER_ADMIN' : 'PENDING';

        if (process.env.NODE_ENV === 'production') {
          return res.status(409).json({ success: false, error: 'ORGANIZATION_REQUIRED', message: 'انضم إلى مؤسسة أو أنشئ مؤسسة قبل إكمال تسجيل Google.' });
        }
        user = await db.createUserAsync({
          email: emailNorm,
          fullName: profile.name || emailNorm.split('@')[0],
          avatarUrl: profile.picture,
          role: assignedRole,
          emailVerified: profile.email_verified,
          phoneVerified: false,
          authProviders: ['google'],
          googleId: profile.sub,
          isActive: true,
        });
      }
    }

    const { token, org, requiresOnboarding: isNewUserPendingOnboarding } = await generateLoginContextAsync(user);

    const logOrgId = org?.id || 'platform';
    db.logAction(logOrgId, user.id, user.email, 'LOGIN_GOOGLE_CREDENTIAL', 'User', user.id, {
      isPendingOnboarding: isNewUserPendingOnboarding,
    }, req.ip);

    return res.json({
      success: true,
      token,
      user: await formatUserResponseAsync(user),
      organization: org || null,
      status: isNewUserPendingOnboarding ? 'PENDING_ONBOARDING' : 'AUTHENTICATED',
      requiresOnboarding: isNewUserPendingOnboarding,
      message: isNewUserPendingOnboarding
        ? 'تم التحقق من حساب Google بنجاح. يرجى اختيار الانضمام لمدرسة أو تسجيل مدرسة جديدة.'
        : 'تم تسجيل الدخول بواسطة حساب Google بنجاح',
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ====================================================================
// 4. PASSWORD RESET & EMAIL VERIFICATION FLOWS
// ====================================================================

// POST /api/v1/auth/forgot-password (Safe user enumeration protected)
authRouter.post('/forgot-password', forgotPasswordLimiter, async (req: express.Request, res: express.Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'EMAIL_REQUIRED', message: 'البريد الإلكتروني مطلوب' });
    }

    const cleanEmail = sanitizeString(email).toLowerCase();
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ success: false, error: 'INVALID_EMAIL', message: 'صيغة البريد الإلكتروني غير صالحة' });
    }

    const user = await db.findUserByEmailAsync(cleanEmail);
    let resetTokenValue: string | undefined = undefined;

    if (user && user.isActive) {
      const rawToken = generateSecureToken(32);
      const tokenHash = hashOtp(rawToken);
      db.createPasswordResetToken(user.id, user.email, tokenHash, 60);
      resetTokenValue = rawToken;

      const org = user.organizationId ? await db.getOrganizationByIdAsync(user.organizationId) : undefined;
      // Send transactional password reset email asynchronously
      emailService.sendPasswordResetEmail({
        to: user.email,
        recipientName: user.fullName,
        resetToken: rawToken,
        tenantSlug: org?.slug,
        orgName: org?.name,
      }).catch((err) => {
        console.error('[Auth] Failed to send password reset email:', err);
      });

      db.logAction(user.organizationId, user.id, user.email, 'REQUEST_PASSWORD_RESET', 'User', user.id, {}, req.ip);
    }

    // Always return safe friendly success message regardless of existence (Anti-Enumeration)
    return res.json({
      success: true,
      message: 'إذا كان البريد الإلكتروني مسجلاً لدينا، فستتلقى تعليمات استعادة كلمة المرور قريباً.',
      ...(process.env.NODE_ENV !== 'production' && resetTokenValue ? { devResetToken: resetTokenValue } : {}),
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/reset-password (Set new password with token)
authRouter.post('/reset-password', async (req: express.Request, res: express.Response) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_FIELDS',
        message: 'رمز الاستعادة وكلمة المرور الجديدة مطلوبان',
      });
    }

    const pStrength = validatePasswordStrength(newPassword);
    if (!pStrength.isValid) {
      return res.status(400).json({
        success: false,
        error: 'WEAK_PASSWORD',
        message: pStrength.message,
      });
    }

    // Find active token by matching hash
    const resetRecord = Array.from(
      (db as unknown as { passwordResetTokens: Map<string, unknown> })['passwordResetTokens']?.values() || []
    ).find((r: unknown) => {
      const rec = r as { tokenHash: string; isUsed: boolean; expiresAt: string };
      return !rec.isUsed && new Date(rec.expiresAt).getTime() > Date.now() && verifyOtp(token, rec.tokenHash);
    }) as { id: string; userId: string } | undefined;

    if (!resetRecord) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_OR_EXPIRED_TOKEN',
        message: 'رابط استعادة كلمة المرور غير صالح أو منتهي الصلاحية',
      });
    }

    const user = await db.getUserByIdAsync(resetRecord.userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
    }

    const newHash = hashPassword(newPassword);
    if (!user.organizationId) {
      return res.status(409).json({ success: false, error: 'ORGANIZATION_REQUIRED' });
    }
    await db.updateUserAsync(user.id, user.organizationId, { passwordHash: newHash });
    db.markPasswordResetTokenUsed(resetRecord.id);

    db.logAction(user.organizationId, user.id, user.email, 'RESET_PASSWORD', 'User', user.id, {}, req.ip);

    return res.json({
      success: true,
      message: 'تم تحديث كلمة المرور بنجاح. يمكنك الآن تسجيل الدخول بكلمة المرور الجديدة.',
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/change-password (Authenticated User)
authRouter.post('/change-password', requireAuth, async (req: PlatformRequest, res: express.Response) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = req.user!;

    if (!newPassword) {
      return res.status(400).json({ success: false, error: 'NEW_PASSWORD_REQUIRED', message: 'كلمة المرور الجديدة مطلوبة' });
    }

    // If user has existing password, verify currentPassword
    if (user.passwordHash) {
      if (!currentPassword) {
        return res.status(400).json({ success: false, error: 'CURRENT_PASSWORD_REQUIRED', message: 'كلمة المرور الحالية مطلوبة' });
      }
      if (!verifyPassword(currentPassword, user.passwordHash)) {
        return res.status(400).json({ success: false, error: 'INCORRECT_PASSWORD', message: 'كلمة المرور الحالية غير صحيحة' });
      }
    }

    const pStrength = validatePasswordStrength(newPassword);
    if (!pStrength.isValid) {
      return res.status(400).json({ success: false, error: 'WEAK_PASSWORD', message: pStrength.message });
    }

    const newHash = hashPassword(newPassword);
    const updated = user.organizationId
      ? await db.updateUserAsync(user.id, user.organizationId, { passwordHash: newHash })
      : undefined;

    db.logAction(user.organizationId, user.id, user.email, 'CHANGE_PASSWORD', 'User', user.id, {}, req.ip);

    return res.json({
      success: true,
      message: 'تم تغيير كلمة المرور بنجاح',
      user: updated ? await formatUserResponseAsync(updated) : undefined,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/verify-email/send (Send verification email)
authRouter.post('/verify-email/send', requireAuth, (req: PlatformRequest, res: express.Response) => {
  try {
    const user = req.user!;
    const force = req.body && req.body.force === true;
    if (user.emailVerified && !force && process.env.NODE_ENV === 'production') {
      return res.json({ success: true, message: 'البريد الإلكتروني موثق بالفعل', alreadyVerified: true });
    }

    const rawToken = generateSecureToken(24);
    const tokenHash = hashOtp(rawToken);
    db.createEmailVerificationToken(user.id, user.email, tokenHash);

    db.logAction(user.organizationId, user.id, user.email, 'SEND_EMAIL_VERIFICATION', 'User', user.id, {}, req.ip);

    return res.json({
      success: true,
      message: 'تم إرسال رابط تأكيد البريد الإلكتروني بنجاح',
      ...(process.env.NODE_ENV !== 'production' ? { devVerificationToken: rawToken } : {}),
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/verify-email/confirm (Confirm email token)
authRouter.post('/verify-email/confirm', async (req: express.Request, res: express.Response) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, error: 'TOKEN_REQUIRED', message: 'رمز التأكيد مطلوب' });
    }

    const match = Array.from(
      (db as unknown as { emailVerificationTokens: Map<string, unknown> })['emailVerificationTokens']?.values() || []
    ).find((r: unknown) => {
      const rec = r as { tokenHash: string; isUsed: boolean; expiresAt: string };
      return !rec.isUsed && new Date(rec.expiresAt).getTime() > Date.now() && verifyOtp(token, rec.tokenHash);
    }) as { id: string; userId: string; email: string } | undefined;

    if (!match) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_OR_EXPIRED_TOKEN',
        message: 'رمز التحقق غير صالح أو منتهي الصلاحية',
      });
    }

    const targetUser = await db.getUserByIdAsync(match.userId);
    const updated = targetUser?.organizationId
      ? await db.updateUserAsync(match.userId, targetUser.organizationId, { emailVerified: true })
      : undefined;
    db.markEmailVerificationTokenUsed(match.id);

    return res.json({
      success: true,
      message: 'تم توثيق البريد الإلكتروني بنجاح',
      user: updated ? await formatUserResponseAsync(updated) : undefined,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ====================================================================
// 5. ACCOUNT LINKING & UNLINKING
// ====================================================================

// POST /api/v1/auth/link/google (Link Google account to active user)
authRouter.post('/link/google', requireAuth, async (req: PlatformRequest, res: express.Response) => {
  try {
    const { credential, code } = req.body;
    const user = req.user!;

    let googleSub = '';
    let googleEmail = '';

    if (credential) {
      const verify = await verifyGoogleIdToken(credential);
      if (!verify.success || !verify.profile) {
        return res.status(400).json({ success: false, error: 'INVALID_GOOGLE_TOKEN', message: verify.error });
      }
      googleSub = verify.profile.sub;
      googleEmail = verify.profile.email;
    } else if (code) {
      const host = req.get('host') || 'localhost:3000';
      const protocol = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
      const redirectUri = `${process.env.APP_URL || `${protocol}://${host}`}/api/v1/auth/google/callback`;
      const exchange = await exchangeGoogleCodeForProfile(code, redirectUri);
      if (!exchange.success || !exchange.profile) {
        return res.status(400).json({ success: false, error: 'GOOGLE_EXCHANGE_FAILED', message: exchange.error });
      }
      googleSub = exchange.profile.sub;
      googleEmail = exchange.profile.email;
    } else {
      return res.status(400).json({ success: false, error: 'CREDENTIAL_OR_CODE_REQUIRED' });
    }

    // Check if another user already has this googleId
    const existingGoogle = await db.findUserByGoogleIdAsync(googleSub);
    if (existingGoogle && existingGoogle.id !== user.id) {
      return res.status(400).json({
        success: false,
        error: 'GOOGLE_ACCOUNT_ALREADY_LINKED',
        message: 'حساب Google هذا مرتبط بحساب آخر بالفعل.',
      });
    }

    const updated = user.organizationId
      ? await db.updateUserAsync(user.id, user.organizationId, {
          googleId: googleSub,
          email: googleEmail,
          authProviders: Array.from(new Set([...(user.authProviders || []), 'google'] as AuthProviderType[])),
        })
      : undefined;

    db.logAction(user.organizationId, user.id, user.email, 'LINK_PROVIDER', 'User', user.id, { provider: 'google' }, req.ip);

    return res.json({
      success: true,
      message: 'تم ربط حساب Google بنجاح',
      user: updated ? await formatUserResponseAsync(updated) : undefined,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/link/phone (Link verified phone to active user)
authRouter.post('/link/phone', requireAuth, async (req: PlatformRequest, res: express.Response) => {
  try {
    const { phone, code } = req.body;
    const user = req.user!;

    const phoneNorm = normalizePhoneNumber(phone);
    if (!phoneNorm.isValid) {
      return res.status(400).json({ success: false, error: 'INVALID_PHONE', message: phoneNorm.error });
    }

    const activeOtp = db.getLatestActivePhoneOtp(phoneNorm.e164);
    if (!activeOtp) {
      return res.status(400).json({ success: false, error: 'OTP_NOT_FOUND', message: 'رمز التحقق غير صالح أو منتهي الصلاحية' });
    }

    if (!verifyOtp(code, activeOtp.otpHash)) {
      return res.status(400).json({ success: false, error: 'INVALID_OTP', message: 'رمز التحقق غير صحيح' });
    }

    db.markPhoneOtpUsed(activeOtp.id);

    // Check if phone belongs to another user
    const existingUser = await db.findUserByPhoneAsync(phoneNorm.e164);
    if (existingUser && existingUser.id !== user.id) {
      return res.status(400).json({
        success: false,
        error: 'PHONE_ALREADY_LINKED',
        message: 'رقم الهاتف هذا مرتبط بحساب مستخدم آخر',
      });
    }

    const updated = user.organizationId
      ? await db.updateUserAsync(user.id, user.organizationId, {
          phone: phoneNorm.e164,
          phoneVerified: true,
          authProviders: Array.from(new Set([...(user.authProviders || []), 'phone'] as AuthProviderType[])),
        })
      : undefined;

    db.logAction(user.organizationId, user.id, user.email, 'LINK_PROVIDER', 'User', user.id, { provider: 'phone' }, req.ip);

    return res.json({
      success: true,
      message: 'تم ربط رقم الهاتف بنجاح',
      user: updated ? await formatUserResponseAsync(updated) : undefined,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// DELETE /api/v1/auth/unlink/:provider (Unlink an authentication provider)
authRouter.delete('/unlink/:provider', requireAuth, async (req: PlatformRequest, res: express.Response) => {
  try {
    const provider = req.params.provider as AuthProviderType;
    const user = req.user!;

    if (!['email', 'phone', 'google'].includes(provider)) {
      return res.status(400).json({ success: false, error: 'INVALID_PROVIDER', message: 'مزود الهوية غير صالح' });
    }

    const result = user.organizationId
      ? await db.unlinkAccountProviderAsync(user.id, user.organizationId, provider)
      : { success: false, error: 'USER_NOT_FOUND' };
    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: result.error,
        message:
          result.error === 'CANNOT_UNLINK_LAST_PROVIDER'
            ? 'لا يمكن إلغاء ربط وسيلة تسجيل الدخول الوحيدة المتبقية في حسابك'
            : 'فشل إلغاء ربط المزود',
      });
    }

    db.logAction(user.organizationId, user.id, user.email, 'UNLINK_PROVIDER', 'User', user.id, { provider }, req.ip);

    return res.json({
      success: true,
      message: `تم إلغاء ربط ${provider} بنجاح`,
      user: result.user ? await formatUserResponseAsync(result.user) : undefined,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ====================================================================
// 6. PROFILE & MULTI-TENANT SWITCHER
// ====================================================================

// GET /api/v1/auth/profile (Full User Identity Profile & Memberships)
authRouter.get('/profile', requireAuth, async (req: PlatformRequest, res: express.Response) => {
  try {
    const user = req.user!;
    const organization = req.organization;
    return res.json({
      success: true,
      user: await formatUserResponseAsync(user),
      organization,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// PUT /api/v1/auth/profile (Update User Profile Details)
authRouter.put('/profile', requireAuth, async (req: PlatformRequest, res: express.Response) => {
  try {
    const user = req.user!;
    const { fullName, avatarUrl, phone } = req.body;

    const updates: Partial<User> = {};
    if (fullName) updates.fullName = sanitizeString(fullName);
    if (avatarUrl !== undefined) updates.avatarUrl = sanitizeString(avatarUrl);
    if (phone) {
      const phoneNorm = normalizePhoneNumber(phone);
      if (phoneNorm.isValid) {
        updates.phone = phoneNorm.e164;
      }
    }

    const updated = user.organizationId
      ? await db.updateUserAsync(user.id, user.organizationId, updates)
      : undefined;

    db.logAction(user.organizationId, user.id, user.email, 'UPDATE_PROFILE', 'User', user.id, updates, req.ip);

    return res.json({
      success: true,
      message: 'تم تحديث الملف الشخصي بنجاح',
      user: updated ? await formatUserResponseAsync(updated) : undefined,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/switch-context & /api/v1/auth/switch-organization (Universal Context Switcher)
const handleSwitchContext = async (req: PlatformRequest, res: express.Response) => {
  try {
    const { membershipId, contextType, organizationId, organizationSlug } = req.body;
    const user = req.user!;

    // Case 1: Switch to PERSONAL Space
    if (contextType === 'PERSONAL' || (!membershipId && !organizationId && !organizationSlug && contextType !== 'ORGANIZATION')) {
      const token = generateToken(user, undefined, 'GUEST', undefined, 'PERSONAL');
      return res.json({
        success: true,
        token,
        activeContext: {
          type: 'PERSONAL',
          role: 'GUEST',
          isPersonal: true,
        },
        organization: null,
        activeRole: 'GUEST',
        user: await formatUserResponseAsync(user),
        message: 'تم التبديل بنجاح إلى المساحة الشخصية',
      });
    }

    // Case 2: Switch using verified membershipId (Strict Server-Side Membership Lookup)
    if (membershipId) {
      const membership = await db.getMembershipByIdAsync(membershipId);
      if (!membership || membership.userId !== user.id) {
        return res.status(403).json({
          success: false,
          error: 'INVALID_MEMBERSHIP',
          message: 'العضوية المحددة غير صحيحة أو لا تخص هذا الحساب',
        });
      }

      if (membership.status !== 'ACTIVE') {
        return res.status(403).json({
          success: false,
          error: 'MEMBERSHIP_NOT_ACTIVE',
          message:
            membership.status === 'PENDING_APPROVAL'
              ? 'طلب الانضمام قيد المراجعة والاعتماد من إدارة المدرسة'
              : 'هذه العضوية غير مفعلة حالياً',
        });
      }

      const targetOrg = await db.getOrganizationByIdAsync(membership.organizationId);
      if (!targetOrg || !targetOrg.isActive) {
        return res.status(404).json({
          success: false,
          error: 'ORGANIZATION_NOT_FOUND',
          message: 'المؤسسة التعليمية غير موجودة أو غير نشطة',
        });
      }

      const targetRole = membership.role;
      const token = generateToken(user, targetOrg.id, targetRole, membership.id, 'ORGANIZATION');

      db.logAction(targetOrg.id, user.id, user.email, 'SWITCH_CONTEXT', 'Membership', membership.id, {}, req.ip);

      return res.json({
        success: true,
        token,
        activeContext: {
          type: 'ORGANIZATION',
          membershipId: membership.id,
          organizationId: targetOrg.id,
          organization: targetOrg,
          role: targetRole,
          studentProfileId: membership.studentProfileId,
          classroomId: membership.classroomId,
          isPersonal: false,
        },
        organization: targetOrg,
        activeRole: targetRole,
        user: await formatUserResponseAsync(user),
        message: `تم التبديل بنجاح إلى: ${targetOrg.name}`,
      });
    }

    // Case 3: Switch using organizationId or organizationSlug (Backward compatibility & Super Admin)
    let targetOrg = organizationId ? await db.getOrganizationByIdAsync(organizationId) : undefined;
    if (!targetOrg && organizationSlug) {
      targetOrg = await db.getOrganizationBySlugAsync(organizationSlug);
    }

    if (!targetOrg) {
      return res.status(404).json({ success: false, error: 'ORGANIZATION_NOT_FOUND', message: 'المؤسسة غير موجودة' });
    }

    const membership = await db.getMembershipAsync(user.id, targetOrg.id);
    if (!membership && user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({
        success: false,
        error: 'NO_MEMBERSHIP_IN_ORG',
        message: 'ليس لديك عضوية في هذه المؤسسة التعليمية',
      });
    }

    if (membership && membership.status !== 'ACTIVE' && user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({
        success: false,
        error: 'MEMBERSHIP_NOT_ACTIVE',
        message: 'عضويتك في هذه المؤسسة قيد المراجعة أو غير نشطة',
      });
    }

    const targetRole = membership?.role || user.role;
    const membershipIdResolved = membership?.id;
    const token = generateToken(user, targetOrg.id, targetRole, membershipIdResolved, 'ORGANIZATION');

    db.logAction(targetOrg.id, user.id, user.email, 'SWITCH_ORGANIZATION', 'Organization', targetOrg.id, {}, req.ip);

    return res.json({
      success: true,
      token,
      activeContext: {
        type: 'ORGANIZATION',
        membershipId: membershipIdResolved,
        organizationId: targetOrg.id,
        organization: targetOrg,
        role: targetRole,
        studentProfileId: membership?.studentProfileId,
        classroomId: membership?.classroomId,
        isPersonal: false,
      },
      organization: targetOrg,
      activeRole: targetRole,
      user: await formatUserResponseAsync(user),
      message: `تم التبديل بنجاح إلى: ${targetOrg.name}`,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
};

authRouter.post('/switch-context', requireAuth, handleSwitchContext);
authRouter.post('/switch-organization', requireAuth, handleSwitchContext);

// GET /api/v1/auth/me (Legacy / Context verification)
authRouter.get('/me', requireAuth, async (req: PlatformRequest, res: express.Response) => {
  const activeCtx = req.activeContext || {
    type: req.organization ? ('ORGANIZATION' as const) : ('PERSONAL' as const),
    role: req.user!.role,
    organizationId: req.organization?.id,
    organization: req.organization,
    isPersonal: !req.organization,
  };
  return res.json({
    success: true,
    user: await formatUserResponseAsync(req.user!),
    organization: req.organization,
    activeContext: activeCtx,
    activeRole: req.user!.role,
  });
});

// POST /api/v1/auth/logout
authRouter.post('/logout', requireAuth, (req: PlatformRequest, res: express.Response) => {
  if (req.user && req.organization) {
    db.logAction(req.organization.id, req.user.id, req.user.email, 'LOGOUT', 'User', req.user.id, {}, req.ip);
  }
  return res.json({ success: true, message: 'Logged out successfully' });
});

// ====================================================================
// 7. DEMO SWITCH (FORBIDDEN IN PRODUCTION)
// ====================================================================
authRouter.post('/demo-switch', (req: PlatformRequest, res: express.Response) => {
  // Production security guard: Demo persona switching is forbidden in production environments
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({
      success: false,
      error: 'DEMO_DISABLED',
      message: 'Demo persona switching is disabled in production environment.',
    });
  }

  try {
    const { persona, tenantSlug } = req.body;
    const targetSlug = tenantSlug || 'horizon';
    const org = db.getOrganizationBySlug(targetSlug);

    if (!org) {
      return res.status(404).json({ success: false, error: 'ORGANIZATION_NOT_FOUND', message: 'المؤسسة غير موجودة' });
    }

    let email = 'admin@horizon.edu.sa';
    if (targetSlug === 'horizon') {
      if (persona === 'teacher') email = 'teacher@horizon.edu.sa';
      else if (persona === 'teacher2') email = 'teacher2@horizon.edu.sa';
      else if (persona === 'student') email = 'student@horizon.edu.sa';
      else if (persona === 'student2') email = 'student2@horizon.edu.sa';
      else if (persona === 'parent') email = 'parent@horizon.edu.sa';
      else email = 'admin@horizon.edu.sa';
    } else {
      if (persona === 'teacher') email = 'teacher.sara@elite.edu.sa';
      else if (persona === 'student') email = 'student@elite.edu.sa';
      else email = 'admin@elite.edu.sa';
    }

    const user = db.findUserByEmail(email, org.id);
    if (!user) {
      return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
    }

    const { token, org: generatedOrg, requiresOnboarding } = generateLoginContext(user);

    return res.json({
      success: true,
      token,
      user: formatUserResponse(user),
      organization: generatedOrg || org,
      requiresOnboarding,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ====================================================================
// 8. SCHOOL REGISTRATION WIZARD
// ====================================================================
authRouter.post('/register-school', async (req: PlatformRequest, res: express.Response) => {
  try {
    const { schoolName, slug, legalName, adminName, adminEmail, password, countryCode } = req.body;
    
    // Support either unauthenticated admin or authenticated user (e.g. Google user)
    const authenticatedUser = req.user;
    const resolvedAdminEmail = authenticatedUser?.email || (adminEmail ? sanitizeString(adminEmail).toLowerCase() : '');
    const resolvedAdminName = adminName ? sanitizeString(adminName) : (authenticatedUser?.fullName || resolvedAdminEmail.split('@')[0]);

    if (!schoolName || !slug || !resolvedAdminName || !resolvedAdminEmail) {
      return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'جميع الحقول الأساسية مطلوبة' });
    }

    const cleanSlug = sanitizeString(slug).toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (!cleanSlug || cleanSlug.length < 2) {
      return res.status(400).json({ success: false, error: 'INVALID_SLUG', message: 'معرف المدرسة يجب أن يتكون من حرفين على الأقل' });
    }

    if (!isValidEmail(resolvedAdminEmail)) {
      return res.status(400).json({ success: false, error: 'INVALID_EMAIL', message: 'صيغة البريد الإلكتروني للمدير غير صحيحة' });
    }

    // Check slug uniqueness
    const existing = await db.getOrganizationBySlugAsync(cleanSlug);
    if (existing) {
      return res.status(400).json({ success: false, error: 'SLUG_TAKEN', message: 'اسم المعرف للمدرسة مستخدم بالفعل' });
    }

    const org = await db.createOrganizationAsync({
      name: sanitizeString(schoolName),
      slug: cleanSlug,
      legalName: legalName ? sanitizeString(legalName) : undefined,
      countryCode: countryCode || 'SA',
      timezone: 'Asia/Riyadh',
      locale: 'ar',
      isActive: true,
    });

    let admin: User;
    if (authenticatedUser) {
      // Existing user registered a new school: update active organization & role, add membership
      if (process.env.NODE_ENV !== 'production') {
        db.updateUser(authenticatedUser.id, undefined, {
          organizationId: org.id,
          role: 'ORG_ADMIN',
          fullName: resolvedAdminName,
        });
      }

      await db.addMembershipAsync({
        userId: authenticatedUser.id,
        organizationId: org.id,
        role: 'ORG_ADMIN',
        isDefault: true,
        status: 'ACTIVE',
      });

      admin = process.env.NODE_ENV !== 'production'
        ? db.getUserById(authenticatedUser.id)!
        : (await db.getUserByIdAsync(authenticatedUser.id, org.id)) || authenticatedUser;
    } else {
      const passwordHash = password ? hashPassword(password) : hashPassword('RtiqaAdmin2026!');

      admin = await db.createUserAsync({
        organizationId: org.id,
        fullName: resolvedAdminName,
        email: resolvedAdminEmail,
        passwordHash,
        role: 'ORG_ADMIN',
        emailVerified: true,
        authProviders: ['email'],
        isActive: true,
      });
    }

    const initialAcademicSetup = process.env.NODE_ENV === 'production'
      ? undefined
      : (() => {
          const year = db.createAcademicYear({
            organizationId: org.id,
            name: '2026-2027',
            startDate: '2026-09-01',
            endDate: '2027-06-30',
            isCurrent: true,
          });
          const term = db.createTerm({
            organizationId: org.id,
            academicYearId: year.id,
            name: 'الفصل الدراسي الأول',
            startDate: '2026-09-01',
            endDate: '2027-01-15',
            isCurrent: true,
          });
          const grade = db.createGradeLevel({
            organizationId: org.id,
            name: 'الصف العاشر',
            sequenceOrder: 10,
          });
          const classroom = db.createClassroom({
            organizationId: org.id,
            gradeLevelId: grade.id,
            name: 'شعبة 10-أ',
            capacity: 30,
          });
          const subject = db.createSubject({
            organizationId: org.id,
            name: 'الرياضيات العامة',
            code: 'MATH-10',
            color: '#10b981',
            description: 'منهج الرياضيات للمرحلة الثانوية',
          });
          return {
            academicYearId: year.id,
            termId: term.id,
            gradeLevelId: grade.id,
            classroomId: classroom.id,
            subjectId: subject.id,
          };
        })();

    db.logAction(org.id, admin.id, admin.email, 'REGISTER_SCHOOL', 'Organization', org.id, {
      schoolName,
      slug: cleanSlug,
    }, req.ip);

    const membership = await db.getMembershipAsync(admin.id, org.id);
    const token = generateToken(admin, org.id, membership?.role || 'ORG_ADMIN', membership?.id, 'ORGANIZATION');

    return res.json({
      success: true,
      token,
      user: await formatUserResponseAsync(admin),
      organization: org,
      initialAcademicSetup,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ====================================================================
// 9. INVITATIONS SYSTEM
// ====================================================================

// POST /api/v1/auth/invitations
authRouter.post(
  '/invitations',
  requireAuth,
  requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']),
  inviteLimiter,
  async (req: PlatformRequest, res: express.Response) => {
    try {
      const { email, role, fullName, classroomId, teacherSpecialization, studentIdNumber, expiresInDays = 7 } = req.body;

      if (!email || !role) {
        return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'البريد الإلكتروني والدور مطلوبين' });
      }

      const normalizedEmail = sanitizeString(email).toLowerCase();
      if (!isValidEmail(normalizedEmail)) {
        return res.status(400).json({ success: false, error: 'INVALID_EMAIL', message: 'صيغة البريد الإلكتروني غير صالحة' });
      }

      const validRoles: UserRole[] = ['ORG_ADMIN', 'TEACHER', 'STUDENT', 'PARENT'];
      if (!validRoles.includes(role as UserRole)) {
        return res.status(400).json({ success: false, error: 'INVALID_ROLE', message: 'الدور المحدد غير صالح' });
      }

      const existingUser = await db.findUserByEmailAsync(normalizedEmail, req.organization!.id);
      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: 'USER_EXISTS',
          message: 'المستخدم مسجل بالفعل في هذه المدرسة',
        });
      }

      if (classroomId && !(await db.isClassroomInOrgAsync(classroomId, req.organization!.id))) {
        return res.status(400).json({
          success: false,
          error: 'INVALID_CLASSROOM',
          message: 'الشعبة المحددة غير موجودة في المؤسسة',
        });
      }

      const inviteCode = generateInviteCode();
      const expiresAt = new Date(Date.now() + Math.max(1, Number(expiresInDays)) * 24 * 60 * 60 * 1000).toISOString();

      const invitation = await db.createInvitationAsync({
        organizationId: req.organization!.id,
        email: normalizedEmail,
        role: role as UserRole,
        inviteCode,
        fullName: fullName ? sanitizeString(fullName) : undefined,
        classroomId,
        teacherSpecialization: teacherSpecialization ? sanitizeString(teacherSpecialization) : undefined,
        studentIdNumber: studentIdNumber ? sanitizeString(studentIdNumber) : undefined,
        createdBy: req.user!.id,
        expiresAt,
      });

      db.logAction(
        req.organization!.id,
        req.user!.id,
        req.user!.email,
        'CREATE_INVITATION',
        'Invitation',
        invitation.id,
        { email: normalizedEmail, role, inviteCode },
        req.ip
      );

      // Send transactional invitation email asynchronously
      emailService.sendSchoolInvitationEmail({
        to: normalizedEmail,
        recipientName: fullName ? sanitizeString(fullName) : undefined,
        inviteCode,
        role: role as string,
        orgName: req.organization?.name,
      }).catch((err) => {
        console.error('[Auth] Failed to send invitation email:', err);
      });

      return res.json({
        success: true,
        data: {
          ...invitation,
          inviteLink: `/platform/invite/${inviteCode}`,
        },
      });
    } catch {
      return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
    }
  }
);

// GET /api/v1/auth/invitations
authRouter.get(
  '/invitations',
  requireAuth,
  requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']),
  async (req: PlatformRequest, res: express.Response) => {
    try {
      const invitations = await db.getInvitationsByOrgAsync(req.organization!.id);
      return res.json({
        success: true,
        data: invitations,
      });
    } catch {
      return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
    }
  }
);

// DELETE /api/v1/auth/invitations/:id
authRouter.delete(
  '/invitations/:id',
  requireAuth,
  requireRoles(['ORG_ADMIN', 'SUPER_ADMIN']),
  async (req: PlatformRequest, res: express.Response) => {
    try {
      const { id } = req.params;
      const revoked = await db.revokeInvitationAsync(id, req.organization!.id);
      if (!revoked) {
        return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'الدعوة غير موجودة' });
      }

      db.logAction(req.organization!.id, req.user!.id, req.user!.email, 'REVOKE_INVITATION', 'Invitation', id, {}, req.ip);
      return res.json({ success: true, message: 'Invitation revoked successfully' });
    } catch {
      return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
    }
  }
);

// GET /api/v1/auth/invitations/verify
authRouter.get('/invitations/verify', async (req: express.Request, res: express.Response) => {
  try {
    const code = req.query.code as string;
    if (!code) {
      return res.status(400).json({ success: false, error: 'CODE_REQUIRED', message: 'رمز الدعوة مطلوب' });
    }

    const invitation = await db.getInvitationByCodeAsync(code);
    if (!invitation) {
      return res.status(404).json({ success: false, error: 'INVALID_CODE', message: 'رمز الدعوة غير صحيح أو غير موجود' });
    }

    if (invitation.isUsed) {
      return res.status(400).json({ success: false, error: 'ALREADY_USED', message: 'تم استخدام رمز الدعوة هذا مسبقاً' });
    }

    if (new Date(invitation.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({ success: false, error: 'EXPIRED', message: 'انتهت صلاحية رمز الدعوة' });
    }

    const org = await db.getOrganizationByIdAsync(invitation.organizationId);

    return res.json({
      success: true,
      data: {
        code: invitation.inviteCode,
        email: invitation.email,
        fullName: invitation.fullName,
        role: invitation.role,
        classroomName: invitation.classroomName,
        teacherSpecialization: invitation.teacherSpecialization,
        organization: {
          id: org?.id,
          name: org?.name,
          slug: org?.slug,
          logoUrl: org?.logoUrl,
        },
        expiresAt: invitation.expiresAt,
      },
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/invitations/accept
authRouter.post('/invitations/accept', acceptInviteLimiter, async (req: express.Request, res: express.Response) => {
  try {
    const { code, fullName, password } = req.body;
    if (!code || !password) {
      return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'رمز الدعوة وكلمة المرور مطلوبان' });
    }

    if (typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ success: false, error: 'WEAK_PASSWORD', message: 'كلمة المرور يجب أن لا تقل عن 6 أحرف' });
    }

    const invitation = await db.getInvitationByCodeAsync(code);
    if (!invitation) {
      return res.status(404).json({ success: false, error: 'INVALID_CODE', message: 'رمز الدعوة غير صحيح' });
    }

    if (invitation.isUsed) {
      return res.status(400).json({ success: false, error: 'ALREADY_USED', message: 'تم استخدام رمز الدعوة هذا مسبقاً' });
    }

    if (new Date(invitation.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({ success: false, error: 'EXPIRED', message: 'انتهت صلاحية رمز الدعوة' });
    }

    const existing = await db.findUserByEmailAsync(invitation.email, invitation.organizationId);
    if (existing) {
      return res.status(400).json({ success: false, error: 'USER_EXISTS', message: 'الحساب مفعل مسبقاً' });
    }

    const passwordHash = hashPassword(password);
    const resolvedName = fullName ? sanitizeString(fullName) : invitation.fullName || invitation.email.split('@')[0];

    const newUser = await db.createUserAsync({
      organizationId: invitation.organizationId,
      email: invitation.email,
      fullName: resolvedName,
      passwordHash,
      role: invitation.role,
      classroomId: invitation.classroomId,
      teacherSpecialization: invitation.teacherSpecialization,
      studentIdNumber: invitation.studentIdNumber || (invitation.role === 'STUDENT' ? `STD-${Date.now().toString().slice(-5)}` : undefined),
      emailVerified: true,
      authProviders: ['email'],
      isActive: true,
    });

    const claimed = await db.markInvitationUsedAsync(invitation.id, invitation.organizationId);
    if (!claimed) {
      return res.status(409).json({ success: false, error: 'INVITATION_UNAVAILABLE', message: 'الدعوة مستخدمة أو منتهية الصلاحية' });
    }

    const org = await db.getOrganizationByIdAsync(invitation.organizationId);
    const membership = await db.getMembershipAsync(newUser.id, invitation.organizationId);
    const token = generateToken(newUser, invitation.organizationId, membership?.role || invitation.role, membership?.id, 'ORGANIZATION');

    db.logAction(
      invitation.organizationId,
      newUser.id,
      newUser.email,
      'ACCEPT_INVITATION',
      'User',
      newUser.id,
      { inviteCode: invitation.inviteCode, role: newUser.role },
      req.ip
    );

    return res.json({
      success: true,
      token,
      user: await formatUserResponseAsync(newUser),
      organization: org,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// POST /api/v1/auth/join-school (Authenticated user joins school using invite code)
authRouter.post('/join-school', acceptInviteLimiter, async (req: PlatformRequest, res: express.Response) => {
  try {
    const { inviteCode } = req.body;
    const user = req.user;

    if (!user) {
      return res.status(401).json({ success: false, error: 'UNAUTHORIZED', message: 'يرجى تسجيل الدخول أولاً' });
    }

    if (!inviteCode) {
      return res.status(400).json({ success: false, error: 'CODE_REQUIRED', message: 'رمز الدعوة مطلوب' });
    }

    const invitation = await db.getInvitationByCodeAsync(inviteCode);
    if (!invitation) {
      return res.status(404).json({ success: false, error: 'INVALID_CODE', message: 'رمز الدعوة غير صحيح' });
    }

    if (invitation.isUsed) {
      return res.status(400).json({ success: false, error: 'ALREADY_USED', message: 'تم استخدام رمز الدعوة هذا مسبقاً' });
    }

    if (new Date(invitation.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({ success: false, error: 'EXPIRED', message: 'انتهت صلاحية رمز الدعوة' });
    }

    // Check if user already has active membership in this org
    const existingMembership = await db.getMembershipAsync(user.id, invitation.organizationId);
    if (existingMembership) {
      return res.status(400).json({ success: false, error: 'ALREADY_MEMBER', message: 'لديك عضوية بالفعل في هذه المدرسة' });
    }

    // Add membership
    await db.addMembershipAsync({
      userId: user.id,
      organizationId: invitation.organizationId,
      role: invitation.role,
      isDefault: !user.organizationId,
      status: 'ACTIVE',
      classroomId: invitation.classroomId,
      teacherSpecialization: invitation.teacherSpecialization,
      studentIdNumber: invitation.studentIdNumber,
    });

    // Update user active role/org if user was pending
    const updates: Partial<User> = {};
    if (!user.organizationId || user.role === 'PENDING' || user.role === 'GUEST') {
      updates.organizationId = invitation.organizationId;
      updates.role = invitation.role;
      if (invitation.classroomId) updates.classroomId = invitation.classroomId;
      if (invitation.teacherSpecialization) updates.teacherSpecialization = invitation.teacherSpecialization;
      if (invitation.studentIdNumber) updates.studentIdNumber = invitation.studentIdNumber;
    }

    if (process.env.NODE_ENV !== 'production') {
      db.updateUser(user.id, undefined, updates);
    } else if (user.organizationId === invitation.organizationId) {
      await db.updateUserAsync(user.id, invitation.organizationId, updates);
    }
    const claimed = await db.markInvitationUsedAsync(invitation.id, invitation.organizationId);
    if (!claimed) {
      return res.status(409).json({ success: false, error: 'INVITATION_UNAVAILABLE', message: 'الدعوة مستخدمة أو منتهية الصلاحية' });
    }

    const updatedUser = process.env.NODE_ENV !== 'production'
      ? db.getUserById(user.id)!
      : (await db.getUserByIdAsync(user.id, user.organizationId))!;
    const org = await db.getOrganizationByIdAsync(invitation.organizationId);
    const membership = await db.getMembershipAsync(user.id, invitation.organizationId);
    const token = generateToken(updatedUser, invitation.organizationId, membership?.role || invitation.role, membership?.id, 'ORGANIZATION');

    db.logAction(
      invitation.organizationId,
      user.id,
      user.email,
      'JOIN_SCHOOL_INVITATION',
      'User',
      user.id,
      { inviteCode: invitation.inviteCode, role: invitation.role },
      req.ip
    );

    return res.json({
      success: true,
      token,
      user: await formatUserResponseAsync(updatedUser),
      organization: org,
      message: `تم الانضمام بنجاح إلى مدرسة: ${org?.name}`,
    });
  } catch {
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});
