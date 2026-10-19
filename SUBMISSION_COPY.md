# AgentShield — submission copy

## Team
**Kartavya** — Krishna Jaiswal, Vijender Kumar, Prashant Gangwar, Jai Gangwar

## Short description
AgentShield is an AI-agent security gateway that checks proposed tool actions before execution. It combines an ASI:One-compatible uAgents entry point with deterministic policy enforcement, sandboxed tools, exact-action approval and an auditable execution record. Safe actions can proceed, forbidden actions are blocked, and sensitive actions wait for human review.

## Problem
AI agents can use tools, not just generate text. Instructions embedded in untrusted files or webpages can steer an agent away from a user's goal, while overly broad permissions can allow data exposure or unsafe side effects. Prompt warnings alone do not prove an action was stopped.

## Solution
AgentShield treats the LLM as an action proposer, never as the final security authority. A server-side policy gateway validates tool names and arguments, applies allow/deny rules, blocks fake-secret disclosure and unapproved recipients, and requires approval for mock email sending. Only approved document reads and simulated email operations are available in this MVP. Each attempt is logged with its decision, reason and actual execution status.

## Target users
Developers and small teams prototyping AI agents that access documents, email-like tools or internal APIs.

## Tech stack
Python, Fetch.ai uAgents, uAgents chat protocol for ASI:One compatibility, ASI1 chat-completions API for structured action proposals (when configured), deterministic Python policy rules, sandboxed mock tools, SQLite and pytest.

## Demonstrated impact
The local prototype demonstrates three repeatable outcomes: a safe document read executes; a fake-secret leak is blocked before the mock tool runs; and a sensitive mock email remains pending until the original requester approves the exact action. Thirteen local automated tests pass. The suite covers strict argument schemas, path restrictions, secret redaction, one-time approval and fail-closed model API errors. Agentverse registration, ASI:One discoverability, public repository publication, customer adoption, and general attack-detection rates are not claimed as complete until independently verified.

## Important limitation
This is a student MVP, not a production security product. Email is simulated; no real email is sent. Secret detection uses simple illustrative checks and cannot catch every attack. The gateway protects only tools that actually pass through it.
