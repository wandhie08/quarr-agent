"""
main.py - QUARR Agent CLI

Entrypoint interaktif untuk pentest agent.
Menangani engagement setup dan agent loop.
"""

import asyncio
import json
import sys
import os
import logging
from datetime import datetime
from pathlib import Path

from quarr.core.models import Engagement, PentestState
from quarr.core.agent import QuarrAgent
from quarr.core.reporter import (
    generate_executive_summary, generate_technical_report,
    export_markdown, export_json
)
from quarr.core.persistence import save_state, load_state, list_engagements
from quarr.core.planner import generate_plan, AttackPlan
from quarr.core.retest import get_retestable_findings, suggest_retest_tools, retest_summary


# === Load .env ===

def load_env(env_path: str = ".env"):
    """Load environment variables from .env file."""
    p = Path(env_path)
    if not p.exists():
        return
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()
                if key and key not in os.environ:
                    os.environ[key] = value

load_env()


# === Logging Setup ===

LOG_FILE = "quarr.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stderr),
    ]
)
logger = logging.getLogger("quarr.main")


# === Engagement Setup ===

def setup_engagement() -> Engagement:
    """
    Interactive engagement setup.
    User harus mendefinisikan scope sebelum agent bisa jalan.
    """
    print("\n" + "=" * 60)
    print("  QUARR — Cyber Operations Agent")
    print("  One Agent. Red. Blue. Forensics.")
    print("=" * 60)

    print("\n📋 ENGAGEMENT SETUP")
    print("─" * 40)

    name = input("Assessment name: ").strip()
    if not name:
        name = f"Assessment-{datetime.now().strftime('%Y%m%d-%H%M')}"

    print("\n🎯 Define authorized scope")
    print("   Enter targets one per line (IP, CIDR, hostname)")
    print("   Press Enter on empty line when done.")

    allowed = []
    while True:
        target = input("  + target: ").strip()
        if not target:
            break
        allowed.append(target)

    if not allowed:
        print("⚠️  No targets defined. At least one target is required.")
        sys.exit(1)

    print("\n🚫 Define excluded targets (optional)")
    print("   Press Enter on empty line to skip.")

    excluded = []
    while True:
        target = input("  - exclude: ").strip()
        if not target:
            break
        excluded.append(target)

    # Define allowed operations — all registered tools
    from tools import get_available_tools
    allowed_ops = get_available_tools()

    engagement = Engagement(
        name=name,
        allowed_targets=allowed,
        excluded_targets=excluded,
        allowed_operations=allowed_ops,
    )

    print("\n✅ ENGAGEMENT CONFIGURED")
    print(f"   Name: {engagement.name}")
    print(f"   ID: {engagement.id}")
    print(f"   Scope: {', '.join(engagement.allowed_targets)}")
    if engagement.excluded_targets:
        print(f"   Excluded: {', '.join(engagement.excluded_targets)}")
    print(f"   Allowed tools: {', '.join(engagement.allowed_operations)}")
    print("─" * 40)

    return engagement


# === Status Callback ===

async def print_status(message: str):
    """Print status updates dari agent."""
    print(f"\n{message}")


# === Main Loop ===

async def main():
    # Setup
    engagement = setup_engagement()

    # Detect backend
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if openai_key:
        backend = "openai"
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        print(f"\n🤖 Backend: OpenAI")
        print(f"   Model: {model}")
    else:
        backend = "ollama"
        model = os.environ.get(
            "OLLAMA_MODEL",
            "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest"
        )
        print(f"\n🤖 Backend: Ollama (local)")
        print(f"   Model: {model}")

    agent = QuarrAgent(
        model=model,
        engagement=engagement,
        api_key=openai_key if openai_key else None,
        backend=backend,
    )

    print("\n" + "=" * 60)
    print("  QUARR READY — 92 tools loaded")
    print("  Type your objective. Type 'help' for commands.")
    print("  Type 'state' to see current state.")
    print("  Type 'findings' to see findings.")
    print("  Type 'scope' to show scope info.")
    print("=" * 60)

    while True:
        try:
            print()
            user_input = input("🔐 quarr> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 Session ended.")
            break

        if not user_input:
            continue

        # Built-in commands
        cmd = user_input.lower()

        if cmd in ("quit", "exit", "q"):
            # M9: Auto-save on quit
            if agent.state.tool_history:
                filepath = save_state(agent.state)
                print(f"\n💾 Session auto-saved: {filepath}")
            print("\n👋 Session ended.")
            break

        elif cmd == "state":
            print(f"\n{agent.state.summary()}")
            continue

        elif cmd == "findings":
            if not agent.state.findings:
                print("\n📝 No findings yet.")
            else:
                for f in agent.state.findings:
                    print(f"\n[{f.severity.value.upper()}] {f.title}")
                    print(f"  Status: {f.status.value}")
                    print(f"  Asset: {f.asset}")
                    print(f"  Confidence: {f.confidence}")
                    if f.evidence:
                        print(f"  Evidence: {len(f.evidence)} item(s)")
            continue

        elif cmd == "scope":
            eng = agent.state.engagement
            print(f"\n📋 Engagement: {eng.name}")
            print(f"   Scope: {', '.join(eng.allowed_targets)}")
            if eng.excluded_targets:
                print(f"   Excluded: {', '.join(eng.excluded_targets)}")
            print(f"   Tools: {', '.join(eng.allowed_operations)}")
            continue

        elif cmd == "history":
            if not agent.state.tool_history:
                print("\n📝 No tool executions yet.")
            else:
                for t in agent.state.tool_history:
                    status = "✅" if t.success else "❌"
                    print(
                        f"  {status} {t.tool_name}({t.arguments}) "
                        f"[{t.timestamp.strftime('%H:%M:%S')}]"
                    )
            continue

        elif cmd == "help":
            print("\nCommands:")
            print("  state      - Show current pentest state")
            print("  findings   - Show discovered findings")
            print("  scope      - Show engagement scope")
            print("  history    - Show tool execution history")
            print("  report     - Executive summary in terminal")
            print("  executive  - Export executive summary (markdown)")
            print("  technical  - Export full technical report (markdown)")
            print("  export     - Export findings (JSON)")
            print("  save       - Save session to disk (M9)")
            print("  load       - Load previous session (M9)")
            print("  sessions   - List saved sessions (M9)")
            print("  plan       - Generate attack plan before execution (M10)")
            print("  retest     - Show retest status for findings (M18)")
            print("  quit       - Exit agent")
            print("\nOtherwise, type your pentest instruction/question.")
            continue

        elif cmd == "save":
            filepath = save_state(agent.state)
            print(f"\n✅ State saved: {filepath}")
            print(f"   Engagement: {agent.state.engagement.name}")
            print(f"   Hosts: {len(agent.state.hosts)}, Findings: {len(agent.state.findings)}")
            continue

        elif cmd == "sessions":
            sessions = list_engagements()
            if not sessions:
                print("\n📝 No saved sessions.")
            else:
                print(f"\n📋 Saved Sessions ({len(sessions)}):")
                for s in sessions:
                    print(f"  [{s['id']}] {s['name']}")
                    print(f"    Scope: {', '.join(s['scope'][:3])}")
                    print(f"    Hosts: {s['hosts']}, Findings: {s['findings']}, Tools: {s['tools_run']}")
                    print(f"    Saved: {s['saved_at']}")
            continue

        elif cmd == "load":
            sessions = list_engagements()
            if not sessions:
                print("\n📝 No saved sessions.")
                continue
            print(f"\nSaved Sessions:")
            for i, s in enumerate(sessions, 1):
                print(f"  {i}. [{s['id']}] {s['name']} ({s['findings']} findings)")
            try:
                choice = input("\nLoad session #: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(sessions):
                    loaded = load_state(sessions[idx]["id"])
                    if loaded:
                        agent.state = loaded
                        print(f"\n✅ Loaded: {loaded.engagement.name}")
                        print(f"   Hosts: {len(loaded.hosts)}, Findings: {len(loaded.findings)}")
                    else:
                        print("❌ Failed to load session.")
                else:
                    print("❌ Invalid selection.")
            except (ValueError, EOFError):
                print("❌ Cancelled.")
            continue

        elif cmd.startswith("plan"):
            objective = cmd[4:].strip()
            if not objective:
                objective = input("Plan objective: ").strip()
            if not objective:
                continue
            print("\n🧠 Generating attack plan...")
            try:
                from tools import get_tools_summary
                plan = await generate_plan(
                    agent.client, objective,
                    agent.state.summary(),
                    get_tools_summary(),
                )
                if plan:
                    print(f"\n{plan.summary()}")
                    confirm = input("\nApprove plan? (y/n/modify): ").strip().lower()
                    if confirm == "y":
                        plan.status = "approved"
                        print("\n✅ Plan approved. Executing...")
                        for step in plan.steps:
                            step.status = "running"
                            print(f"\n⚙️ Step {step.step}: {step.tool}({step.arguments})")
                            result = await agent.run(
                                f"Execute: {step.tool} with {json.dumps(step.arguments)}",
                                status_callback=print_status,
                            )
                            step.status = "done"
                            print(f"{'─' * 40}")
                            print(result[:500])
                        plan.status = "completed"
                        print(f"\n✅ Plan completed.")
                    else:
                        print("Plan not executed.")
                else:
                    print("❌ Could not generate plan.")
            except Exception as e:
                print(f"❌ Plan error: {e}")
            continue

        elif cmd == "retest":
            print(f"\n{retest_summary(agent.state)}")
            retestable = get_retestable_findings(agent.state)
            if retestable:
                print("\nTo retest, type: retest <finding_id>")
            continue

        elif cmd.startswith("retest "):
            finding_id = cmd.split(None, 1)[1].strip()
            target_finding = None
            for f in agent.state.findings:
                if f.id == finding_id or finding_id.lower() in f.title.lower():
                    target_finding = f
                    break
            if not target_finding:
                print(f"❌ Finding not found: {finding_id}")
                continue
            suggestions = suggest_retest_tools(target_finding)
            print(f"\n🔄 Retesting: {target_finding.title}")
            print(f"   Suggested tools: {[s['tool'] for s in suggestions]}")
            for sug in suggestions:
                result = await agent.run(
                    f"Retest finding '{target_finding.title}' using {sug['tool']} on {sug['args']}",
                    status_callback=print_status,
                )
                print(f"{'─' * 40}")
                print(result[:500])
            continue

        elif cmd == "report":
            from reporter import generate_executive_summary, generate_technical_report
            print("\n" + generate_executive_summary(agent.state))
            continue

        elif cmd == "executive":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"report_executive_{ts}.md"
            export_markdown(agent.state, filepath, "executive")
            print(f"\n✅ Executive summary exported: {filepath}")
            print(generate_executive_summary(agent.state))
            continue

        elif cmd == "technical":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"report_technical_{ts}.md"
            export_markdown(agent.state, filepath, "technical")
            print(f"\n✅ Technical report exported: {filepath}")
            print(f"   {len(agent.state.findings)} findings documented")
            print(f"   {len(agent.state.tool_history)} tool executions logged")
            continue

        elif cmd == "export":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"findings_{ts}.json"
            export_json(agent.state, filepath)
            print(f"\n✅ Findings exported: {filepath}")
            continue
            continue

        # === Agent Execution ===
        print("\n🧠 Agent thinking...")
        logger.info(f"User query: {user_input}")

        try:
            result = await agent.run(
                user_query=user_input,
                status_callback=print_status,
            )
            print(f"\n{'─' * 60}")
            print(result)
            print(f"{'─' * 60}")

            # M9: Auto-save after each run
            save_state(agent.state)

        except Exception as e:
            logger.exception(f"Agent error: {e}")
            print(f"\n⚠️ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
