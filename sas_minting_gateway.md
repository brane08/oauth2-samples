# Cookie-Based Gateway Authentication with SAS as Token Minting Service

## Master Prompt

You are a senior security architect and Spring Security expert.

Design and reason about an authentication architecture with the following **non-negotiable constraints**:

---

### High-Level Architecture

- External SSO (e.g., Apache httpd, corporate IdP, or proprietary SSO) authenticates the browser and injects a **trusted
  HTTP cookie**.
- A **Gateway / BFF** (Spring Cloud Gateway or equivalent) is the **only browser-facing component**.
- **Spring Authorization Server (SAS)** is **not a login UI** and **does not perform interactive authentication**.
- SAS exists **only to mint OAuth2 access tokens / JWTs** and return them to the gateway for **route injection**.

---

### Authentication Model

- Authentication is **cookie-first**, not redirect-first.
- The gateway validates the external SSO cookie (or trusts a backend header after TLS termination).
- The gateway is responsible for:
    - Session management
    - CSRF protection
    - CORS
    - Request caching / browser navigation
- SAS **never shows a login page** and **never redirects unauthenticated users**.

---

### Spring Authorization Server Constraints

- Disable **form login**, **default login page**, and **interactive UI** entirely.
- SAS authenticates requests **only via a custom authentication filter** that:
    - Extracts identity from a trusted SSO cookie or header
    - Creates a fully authenticated `Authentication` object
    - Uses a custom `AuthenticationProvider`
- Do **not** use `PreAuthenticatedAuthenticationToken`.
- SAS endpoints must return **401 (API-aware AuthenticationEntryPoint)** instead of redirects.
- SAS may use sessions **only for `/oauth2/authorize`**, not for general browsing.
- Token TTL, session TTL, and refresh policy must be explicitly defined and aligned.

---

### OAuth2 Flow Ownership

- The **gateway** is the OAuth2 client.
- The browser never talks to SAS directly.
- SAS mints tokens only after the gateway presents a valid, authenticated request.
- SAS does **not** restore original URLs unless explicitly instructed by the gateway.

---

### Routing & Token Injection

- The gateway:
    - Obtains tokens from SAS
    - Injects access tokens into downstream service routes
    - Refreshes or re-mints tokens as needed
- Downstream services never see cookiesâonly tokens.

---

### Non-Goals (Explicitly Excluded)

- No login pages in SAS
- No direct browser redirects from SAS
- No IdP federation inside SAS
- No reliance on localhost or invalid cookie domains

---

### Deliverables

Provide:

1. A **clear end-to-end request flow** (browser â gateway â SAS â downstream)
2. **Spring Security filter chain responsibilities** for:
    - Gateway
    - SAS
3. **Key configuration principles** (what must be enabled/disabled)
4. **Failure modes** and how they should manifest (401 vs redirect)
5. A **mental model** explaining why this architecture avoids login loops, empty redirects, and request loss

Use precise Spring Security terminology.  
Assume production-grade security expectations.  
Avoid generic OAuth explanationsâfocus on this exact model.

---

## Optional Scope Narrowing

You may optionally assume:

- Redis-backed sessions and PostgreSQL token persistence
- Multi-tenant routing with per-route token audiences
- CLI clients without browser cookies
- Zero request restoration; all navigation is client-driven
