# AI Usage Declaration

This submission was produced with AI assistance, as permitted by the assessment, and I remain fully responsible for the
complete solution: I have read, built, run and reviewed everything in this repository and can explain, trace, diagnose
and modify any part of it.

## Tools used

| Tool | Used for |
| --- | --- |
| **Claude (Anthropic)** - chat-based coding assistant | Turning the written specification into the initial implementation of the API project, the test project, the EF Core model and migration, and the first drafts of `README.md`, `DESIGN-NOTES.md` and `DEFECT-REPORT.md`; discussing design alternatives (audit policy, concurrency token choice, retry/idempotency rules, cache consistency model); reviewing the code for security gaps. |
| **.NET SDK / `dotnet` CLI, EF Core design-time tooling** | Building, running the test suite, generating the `InitialCreate` migration and `scripts/schema.sql` from the model. |
| **Visual Studio / IDE assistance** | Navigation, refactoring, formatting. |
| Documentation and search (Microsoft Learn: ASP.NET Core, EF Core, `System.Security.Cryptography.AesGcm`, rate limiting middleware) | Verifying API behaviour and recommended practices. |

## How the AI output was validated

* Every generated file was reviewed by me before being kept; interpretation choices (e.g. `clientId` = operation key,
  `json.urlId` = destination consistency assertion) are my decisions and are documented in `DESIGN-NOTES.md` §3.
* The complete test suite (integration tests against the real pipeline with a recording mock destination, plus unit
  tests) was executed and is green; it is the primary evidence that the behaviour matches the specification.
* Security-relevant logic (envelope strictness, URL construction, header policy, AES-GCM handling, audit policy) was
  walked through line by line against the requirements in the assessment. An independent review pass over the finished
  code found the defects listed in `DEFECT-REPORT.md` section A (among them a circuit-breaker latch, a cache-invalidation
  race and a regex-anchoring bypass); each was fixed at the root and pinned by a test.

## What was not delegated to AI

* The final decisions on architecture, trade-offs and defaults.
* Verification: building, running, testing, and reading the code.
* This declaration.
