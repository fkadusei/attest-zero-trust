// Attest authorization policies.
//
// THIS FILE IS THE PORTABLE ARTIFACT. Cedar is an open language; the engine is
// swappable. The text below is evaluated in-process by `cedar-wasm` by default,
// and would go to Amazon Verified Permissions **unchanged** — no rewrite, because
// the language is the portable part and the service is not (ADR-015, ADR-005).
//
// ---------------------------------------------------------------------------
// THE STRUCTURE, AND WHY IT IS THIS WAY
//
// Cedar denies by default: a request is allowed only if some `permit` matches and
// no `forbid` does. That default is the foundation — the permits below are
// deliberately NARROW, so that forgetting to write one produces a denial rather
// than an opening.
//
// Two outcomes are possible for a request that ought to fail, and they need
// different defences:
//
//   1. A request that MATCHES a permit it should not. Defended by making every
//      permit require tenant equality, so there is no permit to match.
//
//   2. A request whose attributes are MISSING, so a condition cannot be evaluated
//      and silently does not fire. This is the dangerous one: `principal.tenant !=
//      resource.tenant` is not a safe test if either attribute is absent. Cedar
//      reports an evaluation error and denies, which is correct — but only by
//      accident. The `forbid` below makes it deliberate.
//
// The tenant boundary is therefore a FORBID, not the absence of a permit
// (ADR-006). A forbid cannot be overridden by any permit, in this file or in one
// added later by someone who has not read this comment.
// ---------------------------------------------------------------------------

// ===========================================================================
// 1. THE TENANT BOUNDARY — fail closed
// ===========================================================================

// A principal and a resource in DIFFERENT tenants are never allowed to meet,
// whatever any permit says. This is the rule that has to survive a mistake in the
// permits below.
//
// `has` is used rather than a bare comparison on purpose. If `tenant` were absent
// from either entity, a bare `!=` would be an evaluation error; Cedar would deny,
// but the reason would be "the policy did not evaluate" rather than "the tenants
// differ". Being explicit keeps the denial a decision rather than a side effect.
forbid (principal, action, resource)
when { principal has tenant && resource has tenant && principal.tenant != resource.tenant };

// A resource carrying NO tenant cannot be attributed to anyone, so nobody may
// reach it. This is the case a missing attribute would otherwise fall through:
// with no tenant, no permit below matches, so the request is denied — but again
// only because of the default, not because anything said so.
forbid (principal, action, resource)
when { resource is Evidence && !(resource has tenant) };

// ===========================================================================
// 2. PERMITS — narrow, and every one requires tenant equality
// ===========================================================================

// The principal KINDS this system knows about. Every permit names them
// explicitly.
//
// This is not decoration. A permit that does not constrain the principal type
// grants access to ANY entity carrying a matching `tenant` attribute — including
// one introduced later by someone building an unrelated feature, or one an
// attacker could arrange to have constructed. Constraining the type means a new
// entity kind is denied until someone deliberately adds it here.
//
// A test proved the point: before this, a principal of type `MysteryActor` with a
// matching tenant was ALLOWED.

// Reading evidence that belongs to your own tenant.
permit (principal, action == Action::"ReadEvidence", resource)
when { principal is User || principal is ServiceAccount }
when { resource is Evidence }
when { principal has tenant && resource has tenant && principal.tenant == resource.tenant };

// Writing evidence to your own tenant, and only if your token carried the
// `writer` role. Roles come from the verified token; they are never read from a
// request header.
permit (principal, action == Action::"WriteEvidence", resource)
when { principal is User || principal is ServiceAccount }
when { resource is Evidence }
when { principal has tenant && resource has tenant && principal.tenant == resource.tenant }
when { principal has roles && principal.roles.contains("writer") };

// Creating evidence in your own tenant.
//
// The resource here is the TENANT, not an Evidence, because the record does not
// exist yet — there is nothing to name. Authorising against the tenant asks the
// right question: "may this principal write evidence INTO this tenant?" The tenant
// comes from the verified token, so there is no request parameter that could point
// this at someone else.
permit (principal, action == Action::"CreateEvidence", resource)
when { principal is User || principal is ServiceAccount }
when { resource is Tenant }
when { principal has tenant && resource has tenant && principal.tenant == resource.tenant }
when { principal has roles && principal.roles.contains("writer") };

// Listing the evidence in your own tenant. The resource is the Tenant itself, and
// its `tenant` attribute is its own id — so this reads the same way as every other
// permit rather than inventing a second comparison.
permit (principal, action == Action::"ListEvidence", resource)
when { principal is User || principal is ServiceAccount }
when { resource is Tenant }
when { principal has tenant && resource has tenant && principal.tenant == resource.tenant };
