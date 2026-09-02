"""
main.py - QUARR Agent CLI

Entrypoint interaktif untuk pentest agent.
Menangani engagement setup dan agent loop.
"""

import asyncio
import json
import sys
from datetime import datetime

from quarr.core.agent import QuarrAgent
from quarr.core.audit import AuditLogger
from quarr.core.config import Settings
from quarr.core.exceptions import ConfigValidationError
from quarr.core.logging import bind_correlation_id, configure_logging, get_logger
from quarr.core.models import Engagement
from quarr.core.persistence import list_engagements, load_state, save_state
from quarr.core.planner import generate_plan
from quarr.core.reporter import (
    export_json,
    export_markdown,
)
from quarr.core.retest import get_retestable_findings, retest_summary, suggest_retest_tools

# === Configuration & Logging Setup ===

def bootstrap():
    """
    Load and validate configuration, configure structured logging, and build
    the audit logger. Fails fast (exit code 1) on invalid configuration.
    """
    try:
        settings = Settings()
    except Exception as e:  # pydantic parse error
        # Logging not configured yet; use a minimal fallback.
        configure_logging(level="INFO", fmt="console")
        get_logger("quarr.main").critical("config_parse_failed", error=str(e))
        sys.exit(1)

    configure_logging(level=settings.log_level, fmt=settings.log_format)
    log = get_logger("quarr.main")

    try:
        settings.validate_runtime()
    except ConfigValidationError as e:
        log.critical("config_invalid", **e.to_dict())
        sys.exit(1)

    log.info("config_loaded", **settings.redacted_summary())

    audit_logger = AuditLogger(
        path=settings.audit_log_path,
        rotate_max_bytes=settings.audit_max_bytes,
        rotate_backups=settings.audit_backups,
    )
    return settings, log, audit_logger


settings, logger, audit_logger = bootstrap()


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
    from quarr.tools.registry import get_available_tools

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

    # Backend from validated settings
    backend = settings.resolved_backend()
    if backend == "openai":
        model = settings.openai_model
        openai_key = settings.openai_api_key
        print("\n🤖 Backend: OpenAI")
        print(f"   Model: {model}")
    else:
        model = settings.ollama_model
        openai_key = ""
        print("\n🤖 Backend: Ollama (local)")
        print(f"   Model: {model}")

    try:
        agent = QuarrAgent(
            model=model,
            engagement=engagement,
            api_key=openai_key if openai_key else None,
            backend=backend,
            audit_logger=audit_logger,
        )
    except Exception as e:
        logger.critical("agent_init_failed", error=str(e))
        print(f"\n❌ Failed to initialize agent: {e}")
        sys.exit(1)

    # Phase 6: rich renderer + optional interactive mode.
    from quarr.cli.progress import ProgressReporter
    from quarr.cli.render import get_renderer
    renderer = get_renderer()
    progress = ProgressReporter(renderer)

    _args = globals().get("_args")
    if _args is not None and getattr(_args, "interactive", False):
        from quarr.cli.interactive import run_interactive
        await run_interactive(agent, renderer, status_callback=progress.status)
        return

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
            print("\nSaved Sessions:")
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
                from quarr.tools.registry import get_tools_summary
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
                        print("\n✅ Plan completed.")
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
            from quarr.core.reporter import (
                generate_executive_summary,
            )
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
        cid = bind_correlation_id()
        logger.info("user_query", query=user_input, correlation_id=cid)

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
            logger.error("agent_error", error=str(e), exc_info=True)
            print(f"\n⚠️ Error: {e}")


def parse_args(argv=None):
    """Parse CLI arguments (Phase 6)."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="quarr",
        description="QUARR — Cyber Operations Agent",
    )
    parser.add_argument("--interactive", action="store_true",
                        help="Launch guided interactive mode")
    parser.add_argument("--engagement", metavar="ID",
                        help="Load an existing saved engagement by ID")
    parser.add_argument("--scope", action="append", default=[], metavar="TARGET",
                        help="Authorized target (repeatable)")
    parser.add_argument("--backend", choices=["openai", "ollama"],
                        help="Force LLM backend")
    parser.add_argument("--report", choices=["executive", "technical"],
                        help="Report type for exports")
    return parser.parse_args(argv)


if __name__ == "__main__":
    _args = parse_args()
    asyncio.run(main())

