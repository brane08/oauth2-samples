# Cookie-First SSO + Spring Authorization Server

## Canonical Architecture, Reference, and AI Prompt

---

## 1. Executive Summary

This document defines a **cookie-first SSO architecture** using:

- External SSO (Apache httpd / Ping / SAML / LDAP)
- Spring Cloud Gateway (OAuth2 Client)
- Spring Authorization Server (SAS)

Authentication is **external**. Authorization tokens are **internal**.

Spring Authorization Server **never owns login**, UI, or browser authentication state.

---

## 2. Non-Negotiable Architectural Rules

- Authentication is performed **only** via an external SSO cookie
- SAS:
    - Does NOT render login pages
    - Does NOT use form login
    - Does NOT redirect to /login
    - Does NOT prompt for credentials
- Browser authentication state lives **outside SAS**

---

## 3. Component Responsibilities

### External SSO (httpd)

- Authenticates the user
- Injects identity via cookie
- OAuth-agnostic
- Cookie:
    - Domain=.example.com
    - Path=/
    - Secure
    - HttpOnly
    - SameSite=None

### Gateway (Spring Cloud Gateway)

- Owns browser session
- OAuth2 Client
- Owns redirects and RequestCache
- Never authenticates users

### Authorization Server (SAS)

- Issues OAuth2 / OIDC tokens
- Authenticates exclusively via SSO cookie
- API-only (401 on unauthenticated access)

---

## 4. SAS Authentication Model

- Custom OncePerRequestFilter
- Reads SSO_TOKEN cookie
- Creates UsernamePasswordAuthenticationToken
- Explicitly creates session
- Saves request using RequestCache
- Calls AuthenticationSuccessHandler
- Does NOT continue filter chain after success

---

## 5. Forbidden in SAS

- formLogin
- Login UI
- Browser redirects
- PreAuthenticatedAuthenticationToken
- Anonymous fallback

---

## 6. RequestCache Rules

### Gateway

- REQUIRED
- Saves /oauth2/authorization/**
- Restores original browser request

### SAS

- Optional but scoped
- Save only /oauth2/authorize
- Never save / or /login

---

## 7. TLS & Cookie Reality

- Must use real domain (example.com)
- localhost, .test, .dev are invalid
- CA must be trusted by:
    - Browser (OS trust)
    - JVM truststore (Gateway + SAS)

---

## 8. Known-Good Repo Structure

cookie-first-sso/
âââ httpd/
âââ gateway/
âââ authorization-server/
âââ docs/

---

## 9. Exhaustive AI Prompt

You are a senior security architect designing a cookie-first SSO architecture with Spring Authorization Server.
Authentication is external, SAS never owns login UI or redirects, and authentication is done exclusively via SSO cookie.
Gateway owns browser session, redirects, and OAuth2 client state.
If your solution introduces login UI, formLogin, or browser auth in SAS, it is incorrect.

---

## 10. Final Statement

This document is the canonical reference for cookie-first SSO with Spring Authorization Server.
