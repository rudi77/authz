/**
 * Shared types between the runtime and admin SDK clients.
 *
 * Field shapes mirror the Pydantic schemas in authzkit/service/schemas.py.
 */

export type SubjectType = "user" | "agent" | "service_account" | "api_key";

export interface Subject {
  type: SubjectType;
  userId?: string;
  agentId?: string;
  serviceAccountId?: string;
}

export interface BulkCheck {
  resource: string;
  action: string;
}

export interface BulkCheckResult {
  resource: string;
  action: string;
  allowed: boolean;
  reason: string;
}

export interface ResolvedContext {
  tenantId: string;
  applicationId: string;
  userId: string;
  roles: string[];
  permissions: string[];
}

export interface AuthorizeResult {
  allowed: boolean;
  decision: string;
  reason: string;
  requiredPermission: string;
  matchedPermissions: string[];
}

export interface Tenant {
  id: string;
  slug: string;
  name: string;
  status: string;
}

export interface Application {
  id: string;
  slug: string;
  name: string;
  status: string;
}

export interface Role {
  id: string;
  name: string;
  scope: string;
  applicationId: string | null;
  tenantId: string | null;
  description: string | null;
  isSystem: boolean;
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  applicationId: string | null;
  description: string | null;
}

export interface Membership {
  id: string;
  tenantId: string;
  applicationId: string | null;
  userId: string;
  roles: string[];
  status: string;
}

export interface Agent {
  id: string;
  tenantId: string;
  applicationId: string;
  name: string;
  role: string;
  status: string;
}

/** Wire-format → camelCase converters. Keep here so the rest of the SDK
 *  is camelCase and the JSON layer is the only place we touch snake_case. */
export function subjectToWire(subject: Subject): Record<string, unknown> {
  const out: Record<string, unknown> = { type: subject.type };
  if (subject.userId !== undefined) out.user_id = subject.userId;
  if (subject.agentId !== undefined) out.agent_id = subject.agentId;
  if (subject.serviceAccountId !== undefined)
    out.service_account_id = subject.serviceAccountId;
  return out;
}

export function resolvedContextFromWire(data: Record<string, unknown>): ResolvedContext {
  return {
    tenantId: data.tenant_id as string,
    applicationId: data.application_id as string,
    userId: data.user_id as string,
    roles: (data.roles as string[]) ?? [],
    permissions: (data.permissions as string[]) ?? [],
  };
}

export function authorizeResultFromWire(data: Record<string, unknown>): AuthorizeResult {
  return {
    allowed: !!data.allowed,
    decision: (data.decision as string) ?? "",
    reason: (data.reason as string) ?? "",
    requiredPermission: (data.required_permission as string) ?? "",
    matchedPermissions: (data.matched_permissions as string[]) ?? [],
  };
}

export function tenantFromWire(data: Record<string, unknown>): Tenant {
  return {
    id: data.id as string,
    slug: data.slug as string,
    name: data.name as string,
    status: data.status as string,
  };
}

export function applicationFromWire(data: Record<string, unknown>): Application {
  return tenantFromWire(data) as Application;
}

export function roleFromWire(data: Record<string, unknown>): Role {
  return {
    id: data.id as string,
    name: data.name as string,
    scope: data.scope as string,
    applicationId: (data.application_id as string | null) ?? null,
    tenantId: (data.tenant_id as string | null) ?? null,
    description: (data.description as string | null) ?? null,
    isSystem: !!data.is_system,
  };
}

export function permissionFromWire(data: Record<string, unknown>): Permission {
  return {
    id: data.id as string,
    name: data.name as string,
    resource: data.resource as string,
    action: data.action as string,
    applicationId: (data.application_id as string | null) ?? null,
    description: (data.description as string | null) ?? null,
  };
}

export function membershipFromWire(data: Record<string, unknown>): Membership {
  return {
    id: data.id as string,
    tenantId: data.tenant_id as string,
    applicationId: (data.application_id as string | null) ?? null,
    userId: data.user_id as string,
    roles: (data.roles as string[]) ?? [],
    status: data.status as string,
  };
}

export function agentFromWire(data: Record<string, unknown>): Agent {
  return {
    id: data.id as string,
    tenantId: data.tenant_id as string,
    applicationId: data.application_id as string,
    name: data.name as string,
    role: (data.role as string) ?? "",
    status: data.status as string,
  };
}
