# Runtime Validation Report

**Generated:** 2026-10-30  
**Target:** CovertScope, local Docker Compose environment

## Summary

| Step | Status | Exit code | Details |
|---|---|---:|---|
| Startup | PASS | n/a | Docker Compose backend and database healthy; dashboard available at `http://localhost:3000` |
| Backend integration | PASS | 0 | 18 tests passed; 4 PostgreSQL subtests passed |
| Frontend unit tests | PASS | 0 | 24 tests passed |
| Frontend production build | PASS | 0 | Vite build succeeded |
| Frontend dependency audit | PASS | 0 | No vulnerabilities reported |
| Browser E2E | PASS | 0 | 4 Playwright tests passed serially |

**Overall:** PASS

## Environment and capability tiers

- **Docker:** AVAILABLE; Compose database and backend containers were healthy.
- **Node.js:** AVAILABLE; v22.
- **Playwright:** AVAILABLE; `@playwright/test` 1.64.1 with the managed Chromium browser.
- **Infrastructure tier:** PRIMARY (Docker-based PostgreSQL).
- **Browser tier:** PRIMARY (Playwright).

## Browser journeys

| Test | Journey and evidence |
|---|---|
| `auth.spec.js` | Rejects an invalid API key, then connects with a valid key; protected API access is checked. |
| `alert-acknowledgement.spec.js` | Acknowledges an alert and verifies the state after reloading the page. Alert data is a stateful browser API fixture. |
| `blocklist-persistence.spec.js` | Adds a reserved test IP through the real API, unblocks it through the UI, and reads back the inactive state. |
| `capture-dashboard.spec.js` | Starts/stops capture through the real backend API and verifies dashboard rendering using deterministic flow/stat fixtures. It does not launch native packet capture or persist synthetic flows. |

The browser suite is configured for one worker to avoid shared-backend test
interference. Test result artifacts are ignored by Git.

## Test-data cleanup

The blocklist journey uses reserved documentation address `192.0.2.254`.
After the run, its fixture row was removed. Earlier simulator test attempts had
created 69 synthetic flows and 2 associated alerts; after confirming those rows
were test-generated, they were removed. Final authenticated API read-back
confirmed 0 flows, 0 alerts, no reserved-IP fixture, and capture stopped.

## Coverage boundaries

- Alert acknowledgement and flow/stat rendering use deterministic browser
  fixtures; these tests verify browser behavior but do not validate persistence
  for those particular API resources.
- Capture start/stop uses the real API, but native packet capture and traffic
  generation were intentionally not run.
- Real PostgreSQL flow ingestion/read-back and IP serialization are covered by
  the backend regression test suite.

## Runtime verdict

```text
environment:
  docker: AVAILABLE — Compose database and backend healthy
  node: AVAILABLE — v22
  playwright: AVAILABLE — @playwright/test 1.64.1; managed Chromium installed
  infra-tier: PRIMARY(Docker-based) — PostgreSQL integration environment
  browser-tier: PRIMARY(Playwright) — 4 browser journeys
startup: PASS — Docker Compose services healthy; dashboard/API reachable
integration: PASS — exit_code: 0, passed: 18 (+ 4 PostgreSQL subtests), failed: 0, skipped: 0
e2e: PASS — exit_code: 0, passed: 4, failed: 0; auth, alert acknowledgement, blocklist persistence, capture/dashboard
overall: PASS — all executed tiers passed; fixture-backed API boundaries are listed above
```
