import express from 'express';
import crypto from 'crypto';
import { db } from './db.ts';
import type { User, UserRole, Organization, OrganizationMembership, ActiveContext, ContextType } from './types.ts';

// Extended Express Request with Tenant and Auth Context
export interface PlatformRequest extends express.Request {
  user?: User;
  organization?: Organization;
  activeContext?: ActiveContext;
  membership?: OrganizationMembership;
}

// In-memory runtime ephemeral secret generated on the fly for non-production environments when AUTH_SECRET is not set
let devRuntimeSecret: string | null = null;

// Validate that AUTH_SECRET is configured in production environment (Fail-Fast)
export function assertProductionAuthSecret(): void {
  const isProduction = process.env.NODE_ENV === 'production';
  const secret = process.env.AUTH_SECRET;
  if (isProduction && (!secret || secret.trim() === '')) {
    throw new Error(
      '[FATAL SECURITY ERROR] AUTH_SECRET environment variable is missing in production. A strong cryptographic secret must be provided via environment variables.'
    );
  }
}

// Retrieve the active signing secret from environment or ephemeral in-memory generator
export function getAuthSecret(): string {
  const isProduction = process.env.NODE_ENV === 'production';
  const secret = process.env.AUTH_SECRET;

  if (isProduction) {
    if (!secret || secret.trim() === '') {
      throw new Error(
        '[FATAL SECURITY ERROR] AUTH_SECRET environment variable is missing in production. A strong cryptographic secret must be provided via environment variables.'
      );
    }
    return secret.trim();
  }

  const envSecret = secret || process.env.JWT_SECRET;
  if (envSecret && envSecret.trim() !== '') {
    return envSecret.trim();
  }

  // In development/test mode without an explicit env variable, generate an ephemeral non-static random secret in RAM
  if (!devRuntimeSecret) {
    devRuntimeSecret = crypto.randomBytes(32).toString('hex');
  }
  return devRuntimeSecret;
}

interface TokenPayload {
  uid: string;
  oid?: string;
  mid?: string;
  ctx?: ContextType;
  role: UserRole;
  email: string;
  exp: number;
}

// Generate cryptographically signed HMAC-SHA256 Token
export function generateToken(
  user: User,
  overrideOrgId?: string,
  overrideRole?: UserRole,
  overrideMembershipId?: string,
  contextType?: ContextType
): string {
  const effectiveOrgId = overrideOrgId !== undefined ? overrideOrgId : user.organizationId;
  const effectiveRole = overrideRole || user.role;
  const effectiveCtx: ContextType = contextType || (effectiveOrgId ? 'ORGANIZATION' : 'PERSONAL');

  const payload: TokenPayload = {
    uid: user.id,
    oid: effectiveOrgId || undefined,
    mid: overrideMembershipId || undefined,
    ctx: effectiveCtx,
    role: effectiveRole,
    email: user.email,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days expiration
  };

  const secret = getAuthSecret();
  const payloadEncoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(payloadEncoded)
    .digest('base64url');

  return `${payloadEncoded}.${signature}`;
}

// Verify and decode HMAC-signed token
export function decodeAndVerifyToken(token: string): TokenPayload | null {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;

    const [payloadEncoded, providedSignature] = parts;
    const secret = getAuthSecret();
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payloadEncoded)
      .digest('base64url');

    // Constant-time signature comparison to prevent timing attacks
    const sigBufferA = Buffer.from(providedSignature);
    const sigBufferB = Buffer.from(expectedSignature);

    if (sigBufferA.length !== sigBufferB.length || !crypto.timingSafeEqual(sigBufferA, sigBufferB)) {
      return null;
    }

    const jsonStr = Buffer.from(payloadEncoded, 'base64url').toString('utf-8');
    const parsed: TokenPayload = JSON.parse(jsonStr);

    // Validate payload fields and expiry (oid and mid are optional)
    if (!parsed.uid || !parsed.role || !parsed.exp) {
      return null;
    }

    if (Date.now() > parsed.exp) {
      // Token expired
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

// Middleware: Extract tenant & auth state from headers and tokens
export const platformAuthMiddleware = (
  req: PlatformRequest,
  res: express.Response,
  next: express.NextFunction
) => {
  void resolvePlatformAuth(req, res, next).catch(next);
};

const resolvePlatformAuth = async (
  req: PlatformRequest,
  res: express.Response,
  next: express.NextFunction
) => {
  const authHeader = req.headers.authorization;
  const tenantHeader = (req.headers['x-tenant-id'] || req.headers['x-tenant-slug']) as string;

  // Public endpoints must not resolve a memory or database tenant before their own guard runs.
  // This also lets production-only endpoints such as demo-switch return their explicit 403.
  if (process.env.NODE_ENV === 'production' && !authHeader) {
    next();
    return;
  }

  // 1. If Bearer token provided
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    const verified = decodeAndVerifyToken(token);

    if (verified) {
      // 1. Identify user strictly by verified.uid (Universal Identity)
      const baseUser = await db.getUserByIdAsync(verified.uid);
      if (baseUser && baseUser.isActive) {
        // If the context is explicitly PERSONAL (or no oid/mid provided):
        if (verified.ctx === 'PERSONAL' || (!verified.oid && !verified.mid)) {
          const userRole = baseUser.role || 'GUEST';
          req.user = {
            ...baseUser,
            organizationId: undefined,
            role: userRole,
          };
          req.organization = undefined;
          req.activeContext = {
            type: 'PERSONAL',
            role: userRole,
            isPersonal: true,
          };
          return next();
        }

        // If a specific membershipId was provided in the token:
        let activeMembership: OrganizationMembership | undefined;
        if (verified.mid) {
          const m = await db.getMembershipByIdAsync(verified.mid);
          if (m && m.userId === baseUser.id && m.status === 'ACTIVE') {
            activeMembership = m;
          }
        }

        // Lookup active membership by (userId, oid)
        if (!activeMembership && verified.oid) {
          const m = await db.getMembershipAsync(baseUser.id, verified.oid);
          if (m && m.status === 'ACTIVE') {
            activeMembership = m;
          }
        }

        // If active membership found for this organization
        if (activeMembership) {
          const org = await db.getOrganizationByIdAsync(activeMembership.organizationId);
          if (org && org.isActive) {
            req.organization = org;
            req.membership = activeMembership;
            req.user = {
              ...baseUser,
              organizationId: org.id,
              role: activeMembership.role,
              classroomId: activeMembership.classroomId || baseUser.classroomId,
              studentIdNumber: activeMembership.studentIdNumber || baseUser.studentIdNumber,
              teacherSpecialization: activeMembership.teacherSpecialization || baseUser.teacherSpecialization,
            };
            req.activeContext = {
              type: 'ORGANIZATION',
              membershipId: activeMembership.id,
              organizationId: org.id,
              organization: org,
              role: activeMembership.role,
              studentProfileId: activeMembership.studentProfileId,
              classroomId: activeMembership.classroomId,
              isPersonal: false,
            };
            return next();
          }
        }

        // Special handling for SUPER_ADMIN when operating on any organization
        if (baseUser.role === 'SUPER_ADMIN' && verified.oid) {
          const org = await db.getOrganizationByIdAsync(verified.oid);
          if (org && org.isActive) {
            req.organization = org;
            req.user = {
              ...baseUser,
              organizationId: org.id,
              role: 'SUPER_ADMIN',
            };
            req.activeContext = {
              type: 'ORGANIZATION',
              organizationId: org.id,
              organization: org,
              role: 'SUPER_ADMIN',
              isPersonal: false,
            };
            return next();
          }
        }

        // If token specified an oid/mid where the user has NO active membership (and is not SUPER_ADMIN),
        // authenticate user in PERSONAL/GUEST context without granting access to the requested org
        req.user = {
          ...baseUser,
          organizationId: undefined,
          role: 'GUEST',
        };
        req.organization = undefined;
        req.activeContext = {
          type: 'PERSONAL',
          role: 'GUEST',
          isPersonal: true,
        };
        return next();
      }
    }
  }

  // 2. Unauthenticated request: Resolve tenant from header if supplied
  if (tenantHeader) {
    const org = await db.getOrganizationByIdAsync(tenantHeader) || await db.getOrganizationBySlugAsync(tenantHeader);
    if (org) {
      req.organization = org;
    }
  }

  // Default fallback for unauthenticated public preview landing
  if (!req.organization) {
    req.organization = await db.getOrganizationBySlugAsync('horizon');
  }

  next();
};

// Guard: Require authenticated user (Identity check)
export const requireAuth = (
  req: PlatformRequest,
  res: express.Response,
  next: express.NextFunction
) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Authentication required. Please sign in.',
    });
  }
  next();
};

// Guard: Require active organization membership (Tenant boundary check)
export const requireOrg = (
  req: PlatformRequest,
  res: express.Response,
  next: express.NextFunction
) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Authentication required. Please sign in.',
    });
  }
  if (!req.organization || !req.user.organizationId || req.user.role === 'PENDING' || req.user.role === 'GUEST') {
    return res.status(403).json({
      success: false,
      error: 'NO_ORGANIZATION_MEMBERSHIP',
      message: 'يتطلب هذا الإجراء الانضمام إلى مدرسة أو مؤسسة تعليمية أولاً.',
    });
  }
  next();
};

// Guard: Require specific user roles
export const requireRoles = (allowedRoles: UserRole[]) => {
  return (req: PlatformRequest, res: express.Response, next: express.NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Authentication required.',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Insufficient permissions for this resource.',
      });
    }

    next();
  };
};
