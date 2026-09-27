# SecureMailScope dashboard

React + TypeScript + Vite + Tailwind front end of SecureMailScope. It talks to the FastAPI backend
(`VITE_API_URL`, default `http://localhost:8000`) and contains no mock data.

```
npm ci
npm run dev -- --host 127.0.0.1 --port 5173   # development server
npm run lint                                  # oxlint
npm run build                                 # type-check + production build
```

Structure: `src/pages` (one page per workflow step), `src/components` (shell, design-system
components, evidence chain, analyst notes), `src/lib/api.ts` (API client), `src/types/api.ts`.
Design rules and tokens: [../DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md). Browser QA: [../qa/README.md](../qa/README.md).
