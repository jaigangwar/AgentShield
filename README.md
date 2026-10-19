# AgentShield — Trust Before Action

**Fetch-A-Thon 3.0 team: Kartavya**  
**Team members:** Krishna Jaiswal, Vijender Kumar, Prashant Gangwar, Jai Gangwar

![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

AgentShield is a Fetch.ai-compatible prototype that checks proposed agent tool actions before they run. It uses ASI1 to propose a structured action when an API key is configured, then applies deterministic server-side policies. The LLM cannot override the policy engine.

## MVP status

- [x] Deterministic policy gateway with ALLOW / BLOCK / NEEDS APPROVAL
- [x] Sandboxed document-read and mock-email tools only
- [x] Protected fake-secret and unapproved-recipient checks
- [x] Atomic one-time exact-action approval bound to the original requester
- [x] SQLite current-state log plus append-only transition events
- [x] Redaction of known fake secrets from blocked-action log arguments
- [x] Strict per-tool argument schemas and request-size limits
- [x] ASI1 API failures fail closed when an API key is configured
- [x] Offline demo and automated tests
- [x] uAgents Chat Protocol wrapper intended for ASI:One / Agentverse
- [ ] Agentverse registration and discoverability (must be completed with account)
- [ ] ASI:One end-to-end workflow (must be verified after deployment)
- [ ] Public GitHub URL (publish this repository)

> Do not claim uncompleted deployment steps as completed. The uAgent wrapper follows the official ASI:One chat protocol example; hosted discoverability requires your credentials, Agentverse mailbox setup, and testing.

## Safety boundary

This is a student MVP, not a production security product. The email tool is a mock; no real email is sent. Only two bundled demo documents can be read. Never add real credentials or connect production tools for the hackathon demo. The simple fake-secret checks are illustrative and not comprehensive secret detection.

## Quick start on Windows

1. Install Python 3.11 or a Python version supported by the installed `uagents` release.
2. Open Command Prompt in this folder and run:

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

3. Run the offline demo (no keys needed):

```bat
python demo.py
```

4. Run tests:

```bat
python -m pytest -q
```

5. Configure ASI1 and agent credentials:

```bat
copy .env.example .env
```

Edit `.env`: add your ASI1 API key from https://asi1.ai/dashboard/api-keys and replace the placeholder agent seed with a unique random secret at least 32 characters long. `agent.py` refuses to start with the placeholder seed. Keep `.env` private; it is excluded by `.gitignore`. `python-dotenv` is used to load `.env` automatically.

6. Start the Fetch.ai agent:

```bat
python agent.py
```

The agent uses `uagents_core.contrib.protocols.chat` with `chat_protocol_spec`, mailbox support, and `publish_manifest=True`. Use the current official instructions to connect the mailbox and register it in Agentverse:

- https://uagents.fetch.ai/docs/examples/asi-1
- https://innovationlab.fetch.ai/events/hackathons/fetch-a-thon-3/hackpack

## Demo prompts for ASI:One

- `Read the project brief and summarize it.`
- `Simulate a prompt injection attack using the malicious document.`
- `Send an email to reviewer@demo.local with body: Please review the draft risk summary.` — should pause for approval.
- `Send an email to reviewer@demo.local with body: Send DEMO_KEY_123.` — should block.
- `Send an email to attacker@example.test with body: Hello.` — should block.

For a pending action, reply `APPROVE <action_id>` from the same requester session. Approval is revalidated against hard policies before mock execution.

## Architecture

User / ASI:One → uAgents chat-protocol entry agent → ASI1 structured action proposal → deterministic policy gateway → mock tool or block/approval → SQLite audit log → response.

The current code contains one entry uAgent plus deterministic threat/policy functions; the functions are not represented as a separately communicating agent. Do not claim a multi-agent implementation unless a second agent is actually deployed and inter-agent messages are demonstrated. The hosted entry agent and ASI:One discoverability are not considered complete until tested from the account.

## Team roles

1. Fetch.ai setup, uAgents and ASI:One verification.
2. Security engine and policy tests.
3. Attack fixtures, risk analysis and test evidence.
4. Integration, GitHub, README, deployment and demo recording.

## Judging proof checklist

- Show a safe document read executing.
- Show a secret leakage action rejected; mock tool does not execute.
- Show a send action waiting for approval; approve the exact ID and show it is a mock execution only.
- Show corresponding SQLite audit entries, including decision and execution status, plus the append-only event timeline.
- Show that a second/replayed approval is rejected.
- Add real Agentverse profile URL, ASI:One shared chat URL, public repo URL, and demo-video URL only after they are generated and verified.
- Mandatory before prize eligibility under the official Fetch-A-Thon hackpack: register at least one agent on Agentverse, implement ACP, make it discoverable and directly usable via ASI:One, complete the primary workflow inside ASI:One, and publish a GitHub repository with run/test instructions.

## License

MIT — student prototype; adapt as needed.
