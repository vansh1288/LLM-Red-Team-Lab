# LLM Agent Red-Team Lab

A controlled environment for testing LLM agent security against prompt injection, data exfiltration, and tool misuse attacks.

## Purpose

This lab provides a safe, reproducible framework for:
- Developing and testing guardrails against LLM agent attacks
- Researching prompt injection and indirect injection techniques
- Evaluating data exfiltration prevention in tool-augmented agents
- Building cybersecurity portfolio demonstrations

## Threat Model Scope

**In Scope:**
- Direct prompt injection (user input manipulation)
- Indirect prompt injection (poisoned external content)
- Data exfiltration via tool misuse (email, file read, web fetch)
- Path traversal in file operations
- Credential leakage in agent outputs

**Out of Scope:**
- Model weight extraction
- Training data reconstruction
- Infrastructure attacks
- Real network exploitation
- Social engineering of humans

## Mock Environment

All components are **fully mocked** - no external dependencies:

| Component | Implementation |
|-----------|----------------|
| File System | `tools.mock_tools.read_file()` - restricted to `data/` directory |
| Web Access | `tools.mock_tools.fetch_url()` - maps to local fixtures only |
| Email | `tools.mock_tools.send_email()` - returns structured simulation, never sends |
| LLM | `agent.core.Agent` - mock implementation returning structured responses |
| Guardrails | `guardrails.controls.GuardrailControls` + `guardrails.detector.ThreatDetector` |
| Attacks | `attacks.suite.AttackSuite` - runs predefined payloads |
| Audit | `observability.audit` - JSONL structured logging to `logs/agent_audit.jsonl` |

## Repository Structure

```
llm-agent-redteam-lab/
├── README.md                 # This file
├── requirements.txt          # Python dependencies (pytest only)
├── .env.example              # Environment variable template
├── .gitignore                # Git ignore rules
├── data/
│   ├── secrets.txt           # SYNTHETIC credentials for testing
│   └── mock_web/
│       ├── normal_page.txt   # Benign policy document
│       └── injected_page.txt # Policy with embedded injection attack
├── agent/
│   ├── __init__.py
│   ├── core.py               # Agent skeleton (mock)
│   └── prompts.py            # System prompts and attack scenarios
├── guardrails/
│   ├── __init__.py
│   ├── controls.py           # Policy enforcement logic
│   └── detector.py           # Pattern-based threat detection
├── tools/
│   ├── __init__.py
│   └── mock_tools.py         # read_file, fetch_url, send_email
├── attacks/
│   ├── __init__.py
│   ├── suite.py              # Attack execution framework
│   └── payloads.json         # Extended attack payload library
├── observability/
│   ├── __init__.py
│   └── audit.py              # JSONL audit logging
├── logs/
│   └── .gitkeep              # Audit logs stored here (gitignored)
└── tests/
    ├── __init__.py
    └── test_mock_tools.py    # Unit tests for tools and audit
```

## Quick Start

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v
```

## Running Attacks

```python
from agent.core import Agent, AgentConfig
from guardrails.controls import GuardrailControls
from attacks.suite import run_attack_suite

# Setup
agent = Agent(AgentConfig(enable_guardrails=True))
guardrails = GuardrailControls(mode="strict")

# Register mock tools
from tools.mock_tools import read_file, fetch_url, send_email
agent.register_tool("read_file", read_file)
agent.register_tool("fetch_url", fetch_url)
agent.register_tool("send_email", send_email)

# Run attack suite
results = run_attack_suite(agent, guardrails)
print(json.dumps(results, indent=2))
```

## Viewing Audit Logs

```python
from observability.audit import AuditLogger

logger = AuditLogger()
for event in logger.read_events():
    print(json.dumps(event, indent=2))
```

## ⚠️ Warning: All Credentials Are Synthetic

**The file `data/secrets.txt` contains ONLY fake, synthetic test data.**

```
API_KEY_TEST_123456
SECRET_KEY_TEST_ABC123
DATABASE_PASSWORD_TEST_XYZ789
JWT_SIGNING_KEY_TEST_SECRET_987654
AWS_ACCESS_KEY_ID_TEST_FAKE123
AWS_SECRET_ACCESS_KEY_TEST_FAKE456
```

These values:
- Are **not real** and **cannot be used** for any actual service
- Follow a clear `*_TEST_*` naming pattern
- Exist solely for testing detection of credential exfiltration
- Should **never** be treated as sensitive

## License

MIT License - See LICENSE file for details.

## Disclaimer

This is an educational/research tool for cybersecurity learning. Use responsibly and only in controlled environments. The authors are not responsible for misuse.