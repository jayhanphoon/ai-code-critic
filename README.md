# ai-code-critic

**AI-powered security code review, right in your terminal.**

`ai-code-critic` scans Python source files for security vulnerabilities using an LLM running behind a local proxy, then displays findings as a colour-coded, severity-ranked table via [Rich](https://github.com/Textualize/rich).

```text
🔍  Security Review — auth.py
┏━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃   # ┃ Finding                        ┃ Severity   ┃ Summary             ┃
┡━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│   1 │ Sensitive Data Exposure in     │    High    │ Password logged in  │
│     │ Logs                           │            │ plain text via      │
│   2 │ Hardcoded Credentials          │    High    │ "admin"/"12345"     │
│   3 │ No Account Lockout             │   Medium   │ Unlimited attempts  │
└─────┴────────────────────────────────┴────────────┴─────────────────────┘
```

---

## Requirements

- **Python 3.10+**
- A **local proxy** running on `localhost:8082` that translates the Anthropic Messages API format to an upstream LLM provider (e.g. [Free Claude Code](https://github.com/your/fcc-server), OpenRouter, or a custom bridge).

---

## Installation

```bash
pip install ai-code-critic
```

Or install from source:

```bash
git clone https://github.com/your-username/ai-code-critic.git
cd ai-code-critic
pip install .
```

---

## Quick Start

```bash
# Review a single file
ai-code-critic auth.py

# Review all .py files in a directory
ai-code-critic src/

# Export the report to a markdown file too
ai-code-critic auth.py -o report.md

# Use a different model
ai-code-critic auth.py --model opencode/deepseek-v4-flash-free
```

---

## Proxy Configuration

The tool expects an Anthropic-compatible proxy at `http://localhost:8082/v1/messages`. This proxy:

1. Receives requests in the [Anthropic Messages API](https://docs.anthropic.com/en/api/messages) format
2. Translates them to the upstream LLM provider of your choice (DeepSeek, OpenRouter, etc.)
3. Streams the response back as SSE (Server-Sent Events)

### Environment Variables

| Variable               | Default    | Description                            |
|------------------------|------------|----------------------------------------|
| `ANTHROPIC_AUTH_TOKEN` | `freecc`   | API key sent as `x-api-key` header     |

### Example: Free Claude Code (fcc-server)

```bash
# Install fcc-server (if that's your proxy)
# ...

# Start the proxy
fcc-server

# Run a review (defaults to port 8082)
ai-code-critic auth.py
```

If your proxy uses a different token, set the environment variable:

```bash
export ANTHROPIC_AUTH_TOKEN="your-token-here"
ai-code-critic auth.py
```

---

## Output

- **Summary table** — all findings with severity, title, and a short description
- **Detail panels** — each finding expanded with OWASP mappings and remediation advice
- **Overall assessment** — a final verdict paragraph extracted from the AI's report

Severity levels are colour-coded:

| Severity    | Colour |
|-------------|--------|
| Critical    | Bold red |
| High        | Red    |
| Medium      | Yellow |
| Low         | Blue   |
| Informational | Cyan |

---

## Project Structure

```
ai-code-critic/
├── reviewer_agent.py      # CLI entry point and core logic
├── pyproject.toml         # Python packaging metadata
├── README.md              # This file
└── .gitignore             # Git exclusion rules
```

---

## Development

```bash
pip install -e .
ai-code-critic --help
```

---

## License

MIT


---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=jayhanphoon/ai-code-critic&type=Date)](https://star-history.com/jayhanphoon/ai-code-critic)
