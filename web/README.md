# Termivar Dashboard Preview

This directory contains a static UI preview for the unreleased Termivar `0.10.0-alpha.1` source line.

> This preview is not production-ready. It is not connected to the Rust API and it does not provide authentication, authorization, or any other security boundary.

## Current behavior

- React renders illustrative, in-memory placeholder data.
- The dashboard makes no API requests.
- The Rust API currently exposes only `GET /health`; this package does not call it.
- Navigation exposes static placeholders only. Scan, backup, deployment, access-control, audit, SLA, and recovery operations are not implemented here.
- A server-render smoke test pins the preview disclosure and verifies that the component tree renders. Component interaction, end-to-end, and accessibility coverage are not implemented.

## Run locally

Use Node.js 24 LTS and npm 11:

```bash
npm ci
npm start
```

The development server opens the static preview at `http://localhost:3000`.

## Quality checks

```bash
npm run type-check
npm run lint
npm test
npm run build
```

`npm run build` writes the static bundle to `dist/`. That bundle is a preview artifact, not a production deployment.

## Status

| Area | Status |
| --- | --- |
| Static dashboard layout | Preview |
| Rust API integration | Not implemented |
| Authentication and authorization | Not implemented |
| Security boundary | None |
| Automated UI tests | Server-render smoke test only |
| Production readiness | Not ready |
