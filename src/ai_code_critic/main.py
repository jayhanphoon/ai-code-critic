#!/usr/bin/env python3
"""
Automated Code Review Agent — CLI Edition

Reviews Python source files for security vulnerabilities using an AI-powered
local proxy, then displays the results as a rich, color-coded table.

Usage:
    python3 reviewer_agent.py path/to/file.py
    python3 reviewer_agent.py path/to/directory/
    python3 reviewer_agent.py *.py

Environment:
    ANTHROPIC_AUTH_TOKEN    Proxy auth token (default: freecc)
    CRITIC_API_KEY          Your API key (bring-your-own-key mode)
    CRITIC_API_URL          API endpoint (default: OpenRouter)
    CRITIC_MODEL            Model name (default: openrouter/auto)
"""

import json
import os
import re
import sys
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
AUTH_TOKEN = os.environ.get("ANTHROPIC_AUTH_TOKEN", "freecc")

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "cyan",
}

console = Console()


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------
PROVIDERS = {
    "proxy": {
        "url": "http://localhost:8082/v1/messages",
        "default_model": "opencode/deepseek-v4-flash-free",
    },
    "ollama": {
        "url": "http://localhost:11434/v1/chat/completions",
        "default_model": "llama3",
    },
}

# ---------------------------------------------------------------------------
# Bring Your Own Key (BYOK) – env-var-driven provider
# ---------------------------------------------------------------------------
CRITIC_API_KEY = os.environ.get("CRITIC_API_KEY", "")
CRITIC_API_URL = os.environ.get(
    "CRITIC_API_URL",
    "https://openrouter.ai/api/v1/chat/completions",
)
CRITIC_MODEL = os.environ.get("CRITIC_MODEL", "openrouter/auto")

if CRITIC_API_KEY:
    PROVIDERS["byok"] = {
        "url": CRITIC_API_URL,
        "default_model": CRITIC_MODEL,
    }


def build_request(provider: str, source_code: str, filename: str, model: str,
                  repair_context: str | None = None) -> tuple:
    """Return ``(url, headers, payload)`` for the given provider.

    When *repair_context* (a bug report from a prior scan) is provided, the
    prompt instructs the model to rewrite the code to fix all issues instead
    of performing a review.
    """
    if repair_context:
        system_prompt = (
            "You are a Senior Security Engineer fixing code vulnerabilities. "
            "Rewrite the given code to fix every security flaw and bug mentioned "
            "in the bug report. Output ONLY the raw corrected code with no "
            "conversational text or markdown code blocks."
        )
        user_message = (
            f"Below is the original file `{filename}` and the bug report:\n\n"
            f"## Original Code\n```python\n{source_code}\n```\n\n"
            f"## Bug Report\n{repair_context}\n\n"
            f"Rewrite this file completely to fix every security flaw and bug "
            f"mentioned. Output ONLY the raw corrected code with no conversational "
            f"text or markdown code blocks."
        )
    else:
        system_prompt = (
            "You are a Senior Security Engineer conducting a code review. "
            "Analyze the provided Python code for security vulnerabilities. "
            "Focus on: authentication bypasses, injection vulnerabilities, "
            "insecure defaults, sensitive data exposure, broken access control, "
            "and any OWASP Top 10 issues. "
            "Provide findings in a clear markdown report format with severity levels. "
            "Format each finding as a markdown heading with severity in parentheses."
        )
        user_message = (
            f"Review this file (`{filename}`) for security bugs:\n\n"
            f"```python\n{source_code}\n```"
        )

    if provider == "proxy":
        url = PROVIDERS["proxy"]["url"]
        headers = {
            "Content-Type": "application/json",
            "x-api-key": AUTH_TOKEN,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": model,
            "max_tokens": 4000,
            "stream": True,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }
    elif provider == "ollama":
        url = PROVIDERS["ollama"]["url"]
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": model,
            "stream": True,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
    elif provider == "byok":
        url = PROVIDERS["byok"]["url"]
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {CRITIC_API_KEY}",
        }
        payload = {
            "model": model,
            "stream": True,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
    else:
        raise ValueError(f"Unknown provider: {provider}")

    return url, headers, payload


# ---------------------------------------------------------------------------
# SSE parsers
# ---------------------------------------------------------------------------
def _parse_sse_anthropic(raw: str) -> str:
    """Parse Anthropic-style SSE (content_block_delta / text_delta)."""
    text_parts: list[str] = []
    for line in raw.splitlines():
        if line.startswith("data: "):
            try:
                data = json.loads(line[6:])
                if (
                    data.get("type") == "content_block_delta"
                    and data.get("delta", {}).get("type") == "text_delta"
                ):
                    text_parts.append(data["delta"]["text"])
            except json.JSONDecodeError:
                continue
    return "".join(text_parts)


def _parse_sse_openai(raw: str) -> str:
    """Parse OpenAI / Ollama-style SSE (choices[*].delta.content)."""
    text_parts: list[str] = []
    for line in raw.splitlines():
        if line.startswith("data: "):
            body = line[6:]
            if body.strip() == "[DONE]":
                continue
            try:
                data = json.loads(body)
                choices = data.get("choices", [])
                if choices:
                    delta = choices[0].get("delta", {})
                    text_parts.append(delta.get("content", ""))
            except json.JSONDecodeError:
                continue
    return "".join(text_parts)


SSE_PARSERS = {
    "proxy": _parse_sse_anthropic,
    "ollama": _parse_sse_openai,
    "byok": _parse_sse_openai,
}


def send_code_for_review(source_code: str, filename: str, model: str, provider: str,
                         repair_context: str | None = None) -> str:
    """Send source code to the chosen provider and return the review text.

    When *repair_context* (a prior bug report) is given the model rewrites the
    code instead of reviewing it.
    """
    url, headers, payload = build_request(provider, source_code, filename, model,
                                          repair_context=repair_context)
    parse_sse = SSE_PARSERS[provider]

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=120, stream=True)
        resp.raise_for_status()
        return parse_sse(resp.text) or "(empty response)"
    except requests.exceptions.ConnectionError:
        raise ConnectionError(f"Cannot reach {provider} at {url}. Is it running?")
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 401 and provider == "proxy":
            raise RuntimeError("Proxy returned 401. Check ANTHROPIC_AUTH_TOKEN.")
        raise RuntimeError(f"{provider} returned HTTP {status}: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Request failed: {e}")


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------
# Match finding headings in any of these formats (tried in order):
#   1. ## [Severity] Title
#   2. ## Finding N: Title (Severity)    or    ## N. Title (Severity)
#   3. ## Title (Severity)
FINDING_PATTERNS = [
    re.compile(r"^#{2,4}\s+\[(.+?)\]\s+(.+)", re.MULTILINE),  # [Severity] Title
    re.compile(
        r"^#{2,4}\s+(?:Finding\s+)?\d+[\.:]\s+(.+?)\s+\((.+?)\)\s*$",
        re.MULTILINE,
    ),  # Finding N: Title (Severity) or N. Title (Severity)
    re.compile(
        r"^#{2,4}\s+(.+?)\s+\((.+?)\)\s*$", re.MULTILINE
    ),  # Title (Severity)
]


def parse_findings(report: str) -> list[dict]:
    """Extract individual findings from the markdown report.

    Returns a list of dicts with keys: title, severity, body.
    Supports several heading formats (see FINDING_PATTERNS).
    """
    # Try each pattern — use the first one that finds anything
    all_matches: list[tuple[int, int, str, str]] = []  # (start, end, title, severity)

    for pat in FINDING_PATTERNS:
        candidates = []
        for m in pat.finditer(report):
            groups = m.groups()
            # Pattern 1: [Severity] Title  → groups = (severity, title)
            # Pattern 2/3: Title (Severity) → groups = (title, severity)
            if pat is FINDING_PATTERNS[0]:
                severity, title = groups[0], groups[1]
            else:
                title, severity = groups[0], groups[1]
            candidates.append((m.start(), m.end(), title.strip(), severity.strip().lower()))

        if candidates:
            all_matches = candidates
            break

    findings: list[dict] = []
    for i, (start, end, title, severity) in enumerate(all_matches):
        body_start = end
        body_end = all_matches[i + 1][0] if i + 1 < len(all_matches) else len(report)
        body = report[body_start:body_end].strip()
        findings.append({"title": title, "severity": severity, "body": body})

    return findings


def extract_overall(report: str) -> str:
    """Grab the final assessment / summary paragraph if present."""
    # Bold inline assessment
    m = re.search(
        r"\*\*Overall Assessment:\*\*\s*(.+?)(?=\n(?:##|\*\*)|\Z)", report, re.DOTALL
    )
    if m:
        return m.group(1).strip()

    # Section like ## Summary / ## Conclusion — grab everything after it (skipping tables)
    m = re.search(
        r"^#{2,4}\s+(?:Summary|Conclusion|Assessment)\b.*$(?:\n(?!##).*)*",
        report,
        re.MULTILINE | re.IGNORECASE,
    )
    if m:
        section = m.group()
        # Strip the heading line + any table rows
        lines = section.split("\n")[1:]
        non_table = [l for l in lines if not l.strip().startswith("|")]
        text = " ".join(l.strip() for l in non_table if l.strip()).strip()
        if text:
            return re.sub(r"\s+", " ", text)
    return ""


# ---------------------------------------------------------------------------
# Display — rich terminal output
# ---------------------------------------------------------------------------
def show_results(filename: str, report: str):
    """Render the full bug report to the terminal with rich formatting."""

    # Header
    console.print()
    console.rule(f"[bold cyan]🔍  Security Review — {filename}[/]")
    console.print()

    findings = parse_findings(report)

    if not findings:
        # Fall back to plain markdown
        console.print(Panel(report, title="Report (raw)", border_style="dim"))
        return

    # Build table
    table = Table(
        title=f"Found {len(findings)} issue(s)",
        title_style="bold",
        border_style="bright_blue",
        header_style="bold white",
        show_lines=False,
        padding=(0, 1),
    )

    table.add_column("#", style="dim", width=3, no_wrap=True)
    table.add_column("Finding", min_width=30, no_wrap=False)
    table.add_column("Severity", width=14, no_wrap=True)
    table.add_column("Summary", min_width=40, no_wrap=False)

    for idx, f in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(f["severity"], "white")
        severity_label = Text(f["severity"].title(), style=color)

        # First ~180 chars of body as summary
        body_clean = re.sub(r"\*\*.*?\*\*", "", f["body"])  # strip bold
        body_clean = re.sub(r"\[.*?\]\(.*?\)", "", body_clean)  # strip links
        body_clean = " ".join(body_clean.split())  # collapse whitespace
        summary = body_clean[:180]
        if len(body_clean) > 180:
            summary += "…"

        table.add_row(str(idx), f["title"], severity_label, summary)

    console.print(table)
    console.print()

    # Detailed findings in collapsible-style panels
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        panel_title = f"[{color}]◆  {f['title']}  ({f['severity'].title()})[/]"
        body_rendered = re.sub(
            r"^(#{1,5})\s+",
            lambda m: f"[bold]{'▸' * (6 - len(m.group(1)))}[/] ",
            f["body"],
            flags=re.MULTILINE,
        )
        console.print(Panel(body_rendered, title=panel_title, border_style=color))
        console.print()

    # Overall assessment
    overall = extract_overall(report)
    if overall:
        console.print(Panel(overall, title="[bold]Overall Assessment[/]", border_style="green"))
        console.print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def collect_python_files(path: str) -> list[Path]:
    """Resolve *path* to one or more ``.py`` files.

    - A single file → just that file.
    - A directory → all ``*.py`` files under it (non-recursive).
    """
    p = Path(path)
    if p.is_file():
        if p.suffix != ".py":
            print(f"Warning: {p} is not a .py file, will still attempt review.", file=sys.stderr)
        return [p]
    elif p.is_dir():
        files = sorted(p.glob("*.py"))
        if not files:
            print(f"Error: no .py files found in {p}", file=sys.stderr)
            sys.exit(1)
        return files
    else:
        print(f"Error: {p} does not exist", file=sys.stderr)
        sys.exit(1)


def main():
    import argparse

    default_provider = "byok" if CRITIC_API_KEY else "proxy"

    parser = argparse.ArgumentParser(
        description="AI-powered security code reviewer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ai-code-critic auth.py\n"
            "  ai-code-critic src/\n"
            "  ai-code-critic *.py --fix\n"
            "  ai-code-critic auth.py --provider ollama\n"
            "\n"
            "BYOK (Bring Your Own Key):\n"
            "  export CRITIC_API_KEY=\"your-key\"\n"
            "  export CRITIC_API_URL=\"https://openrouter.ai/api/v1/chat/completions\"\n"
            "  export CRITIC_MODEL=\"openrouter/auto\"\n"
            "  ai-code-critic auth.py\n"
        ),
    )
    parser.add_argument(
        "target",
        help="Python file or directory to scan for security issues",
    )
    parser.add_argument(
        "--provider",
        choices=list(PROVIDERS),
        default=default_provider,
        help=f"AI backend to use (default: {default_provider}). Choices: {', '.join(PROVIDERS)}",
    )
    parser.add_argument(
        "--model",
        help="Model name (provider-specific default used if omitted)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Also write report to a markdown file",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix discovered bugs using a second AI pass and save to auth_fixed.py",
    )

    args = parser.parse_args()

    provider = args.provider
    model = args.model or PROVIDERS[provider]["default_model"]

    # BYOK hint — shown once when no key is configured
    if not CRITIC_API_KEY:
        console.print(Panel(
            "[bold]BYOK mode:[/] Set [cyan]CRITIC_API_KEY[/], "
            "[cyan]CRITIC_API_URL[/], and [cyan]CRITIC_MODEL[/] "
            "in your environment to use your own AI provider (e.g. OpenRouter).\n\n"
            "  [dim]export CRITIC_API_KEY=\"your-key\"\n"
            "  export CRITIC_MODEL=\"openrouter/auto\"\n"
            "  export CRITIC_API_URL=\"https://openrouter.ai/api/v1/chat/completions\"[/]",
            title="[yellow]ℹ[/]",
            border_style="yellow",
        ))

    files = collect_python_files(args.target)

    for filepath in files:
        try:
            source = filepath.read_text()
        except OSError as e:
            print(f"Error reading {filepath}: {e}", file=sys.stderr)
            continue

        console.print(
            f"Reviewing [bold]{filepath}[/] "
            f"([dim]{len(source)} bytes[/], provider: [cyan]{provider}[/], model: [cyan]{model}[/]) ..."
        )

        try:
            report = send_code_for_review(source, filepath.name, model, provider)
        except (ConnectionError, RuntimeError) as e:
            console.print(f"[red]✗ {e}[/]")
            continue

        # Terminal display
        show_results(filepath.name, report)

        # Optional file output
        if args.output:
            out = Path(args.output)
            out.write_text(report)
            console.print(f"[dim]Report also written to {out}[/]")

        # --fix: second loop — repair
        if args.fix:
            findings = parse_findings(report)
            if findings:
                console.print(f"\n[bold yellow]🔧  {len(findings)} bug(s) found — launching repair loop...[/]\n")
                try:
                    repair_response = send_code_for_review(
                        source, filepath.name, model, provider,
                        repair_context=report,
                    )
                except (ConnectionError, RuntimeError) as e:
                    console.print(f"[red]✗ Repair failed: {e}[/]")
                    continue

                # Strip any markdown code fences the model might add
                fixed_code = repair_response.strip()
                fixed_code = re.sub(r"^```(?:python)?\s*", "", fixed_code)
                fixed_code = re.sub(r"\s*```$", "", fixed_code)

                fixed_path = Path("auth_fixed.py")
                fixed_path.write_text(fixed_code)
                console.print(f"[green]✓  Fixed code saved to {fixed_path}[/]")
            else:
                console.print("[dim]No bugs to fix.[/]")

    console.print(Rule("[green]Done[/]"))


if __name__ == "__main__":
    main()
