'use strict';

/**
 * Signatures of protective code (auth checks, role checks, rate limiters, validators,
 * ownership filters, sanitizers) shared by several check groups. A route is treated as
 * protected when one of these appears in its handler, middleware chain or mount.
 */

const { alt } = require('./util');

// Authentication: something that establishes who the caller is.
const AUTH_WORDS = [
  'requireAuth', 'requireUser', 'requireLogin', 'requireSession', 'requireSignedIn', 'ensureAuthenticated', 'ensureAuth', 'ensureLoggedIn', 'isAuthenticated', 'isLoggedIn',
  'authenticate', 'authenticated', 'authMiddleware', 'authGuard', 'AuthGuard', 'checkAuth', 'verifyAuth', 'verifyToken', 'verifyJwt', 'verifyJWT', 'validateToken', 'withAuth', 'withSession',
  'protectedRoute', 'protectRoute', 'passport.authenticate', 'jwt.verify', 'jwtVerify', 'expressjwt', 'expressJwt', 'getServerSession', 'getSession(', 'auth()', 'auth(req', 'currentUser(',
  'getAuth(', 'clerkMiddleware', 'requireAuth(', 'auth.protect', 'getUser(', 'getUserId(', 'getToken(', 'validateSession', 'validateRequest', 'verifySession', 'lucia.', 'betterAuth',
  'supabase.auth.getUser', 'auth.getUser', 'auth.getClaims', 'getClaims(', 'verifyIdToken', 'admin.auth()', 'UseGuards', '@Authorized', 'session.user', 'req.user', 'req.auth', 'req.session.user',
  'req.session.userId', 'res.locals.user', 'ctx.state.user', 'context.user', 'locals.user', 'event.locals.user', 'request.auth', 'c.get(\'user\')', 'c.get("user")', 'getKindeServerSession',
  'withApiAuthRequired', 'getAccessToken(', 'withPageAuthRequired', 'requireApiKey', 'verifyApiKey', 'checkApiKey', 'x-api-key', 'bearerAuth', 'basicAuth', 'jwt(', 'createRemoteJWKSet',
  'requiresAuth(', 'getCurrentUser(', 'protectedProcedure', 'authedProcedure', 'privateProcedure', 'adminProcedure', 'authedAdminProcedure', 'getServerAuthSession', 'validateRequest(',
];
// Patterns that need word boundaries: auth() / await auth(req), session?.user, tRPC ctx.session / ctx.user.
const AUTH_BOUNDED = String.raw`(?<![\w.$])auth\s*\(|\bsession\??\.(?:user|userId)\b|\bctx\.(?:session|user)\b`;
const AUTH_RE = new RegExp(`${alt(AUTH_WORDS)}|${AUTH_BOUNDED}`);

// Authorization by role: admin-only gates.
const ROLE_RE = /\b(?:adminProcedure|authedAdminProcedure|isAdmin|is_admin|requireAdmin|adminOnly|ensureAdmin|checkAdmin|verifyAdmin|requireRole|requireRoles|hasRole|checkRole|checkRoles|rolesGuard|RolesGuard|authorizeRoles?|requirePermission|hasPermission|checkPermission|ability\.can|isSuperAdmin|isStaff|requireStaff|adminGuard|AdminGuard)\b|\brole\s*[!=]==?\s*['"`](?:admin|owner|superuser|superadmin|staff)['"`]|['"`](?:admin|owner|superuser|superadmin|staff)['"`]\s*[!=]==?\s*[\w.?]*role\b|roles?\??\.includes\(\s*['"`](?:admin|owner|superuser|superadmin|staff)['"`]|app_metadata\??\.(?:role|roles|claims_admin)|publicMetadata\??\.role|sessionClaims|has\(\s*\{\s*(?:role|permission)\s*:|customClaims|claims\??\.admin|@Roles\(/;

// Rate limiting libraries and platform features.
const RATE_LIMIT_RE = /express-rate-limit|\brateLimit\s*\(|\bRateLimit\b|rate-limiter-flexible|RateLimiter(?:Memory|Redis|Postgres|Mongo|Cluster)?\b|@upstash\/ratelimit|\bRatelimit\.(?:slidingWindow|fixedWindow|tokenBucket)|express-slow-down|\bslowDown\s*\(|@fastify\/rate-limit|fastify-rate-limit|koa-ratelimit|koa2-ratelimit|hono-rate-limiter|@hono-rate-limiter|@nestjs\/throttler|ThrottlerModule|ThrottlerGuard|@arcjet\/|\barcjet\s*\(|\bcheckRateLimit\s*\(|@vercel\/firewall|\blimiter\.(?:consume|removeTokens|limit)\s*\(|\bratelimit\.limit\s*\(|@unkey\/ratelimit|next-rate-limit|\brateLimiter\b|\brate_limit\b|\bthrottle\s*\(/;

// Schema validation of request input.
const VALIDATION_RE = /\.(?:parse|safeParse|parseAsync|safeParseAsync)\s*\(|\bvalidate(?:Sync|Async)?\s*\(|\bvalidationResult\s*\(|\bcheckSchema\s*\(|\bcelebrate\s*\(|\bzValidator\s*\(|\bvValidator\s*\(|\btbValidator\s*\(|\bajv\b|\.compile\s*\(|\bschema\s*:\s*\{\s*(?:body|querystring|params)|\bplainToInstance\s*\(|\bValidationPipe\b|\bassert(?:Is)?\s*\(|\bis\(\s*\w+\s*,|\bbody\(\s*['"`]\w+['"`]\s*\)\s*\.\s*(?:is|isEmail|isLength|notEmpty|isString|isInt|trim|escape)|\btypia\.|\bv\.parse\s*\(|\btype\(\s*\{/;
const VALIDATION_LIBS = ['zod', 'joi', '@hapi/joi', 'yup', 'valibot', 'superstruct', 'class-validator', 'express-validator', 'ajv', '@sinclair/typebox', 'celebrate', 'io-ts', 'runtypes', 'arktype', '@vinejs/vine', 'typia', '@effect/schema', 'effect', 'fastest-validator', 'validator'];

// Filters that scope a query to the caller.
const OWNER_RE = /\b(?:user_?id|userId|owner_?id|ownerId|author_?id|authorId|created_?by|createdBy|profile_?id|profileId|customer_?id|customerId|member_?id|uid)\b|auth\.uid\(\)|req\.user|session\??\.user|currentUser|ctx\.state\.user|locals\.user|request\.auth|res\.locals\.user|user\.id\b|userClient\(|getUser\(/;

// HTML sanitizers and escapers: libraries, plus app helpers named for it (sanitizeMarkdown(), escapeHTML(), toSafeHtml()).
const SANITIZER_RE = /\b(?:DOMPurify|dompurify|purify|xss|filterXSS|insane|sanitizer|striptags|stripTags|strip_tags|isomorphic-dompurify)\b|\b[\w$]*(?:[sS]anitiz|[pP]urif|[eE]scape|[cC]leanHtml|[cC]leanHTML|[sS]afeHtml|[sS]afeHTML|[eE]ncodeHtml|[eE]ncodeHTML|[hH]tmlEncode|[hH]tmlEscape)[\w$]*\s*\(|\b(?:he|entities)\.(?:encode|escape)\s*\(/;

module.exports = { AUTH_RE, ROLE_RE, RATE_LIMIT_RE, VALIDATION_RE, VALIDATION_LIBS, OWNER_RE, SANITIZER_RE };
