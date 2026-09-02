"""
interactive.py - Guided interactive mode (Phase 6).

Numbered menu wrapping the agent. All safety checks (policy/scope/approval)
remain in the agent path; this module only orchestrates prompts.
"""

MENU = """
QUARR — Interactive Mode
  1) Run discovery on a target
  2) Review findings
  3) Generate report
  4) Show state
  5) Back to command loop
"""


async def run_interactive(agent, renderer, input_fn=input, status_callback=None):
    """Run the guided menu until the user chooses to exit."""
    while True:
        renderer.info(MENU)
        try:
            choice = str(input_fn("select> ")).strip()
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "1":
            target = str(input_fn("target: ")).strip()
            if target:
                result = await agent.run(
                    f"Run network discovery on {target}",
                    status_callback=status_callback,
                )
                renderer.result_panel(result)
        elif choice == "2":
            renderer.findings_table(agent.state)
        elif choice == "3":
            from quarr.core.reporter import generate_executive_summary

            renderer.result_panel(generate_executive_summary(agent.state))
        elif choice == "4":
            renderer.state_panel(agent.state)
        elif choice in ("5", "q", "quit", "exit", "back"):
            return
        else:
            renderer.info("Invalid choice. Enter 1-5.")
