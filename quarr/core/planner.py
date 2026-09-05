"""
planner.py - M10: Attack Planner

LLM membuat plan sebelum eksekusi. User bisa review/approve.

Flow:
1. User kasih objective
2. LLM buat plan (list of steps + tools)
3. User review: approve / modify / reject
4. Agent eksekusi plan step-by-step
"""

import json
import logging
from dataclasses import dataclass, field

from quarr.tools.registry import TOOL_REGISTRY

logger = logging.getLogger("quarr.planner")


@dataclass
class PlanStep:
    step: int
    tool: str
    description: str
    arguments: dict = field(default_factory=dict)
    status: str = "pending"  # pending, running, done, skipped, failed


@dataclass
class AttackPlan:
    objective: str
    steps: list[PlanStep] = field(default_factory=list)
    current_step: int = 0
    status: str = "draft"  # draft, approved, running, completed

    def summary(self) -> str:
        lines = [
            "📋 ATTACK PLAN",
            f"Objective: {self.objective}",
            f"Status: {self.status}",
            f"Steps: {len(self.steps)}",
            "",
        ]
        for s in self.steps:
            icon = {
                "pending": "⬜", "running": "🔄",
                "done": "✅", "skipped": "⏭️", "failed": "❌"
            }.get(s.status, "⬜")
            args = s.arguments if isinstance(s.arguments, dict) else {}
            args_str = ", ".join(f"{k}={v}" for k, v in args.items())
            lines.append(f"  {icon} {s.step}. {s.tool}({args_str})")
            lines.append(f"     {s.description}")
        return "\n".join(lines)

    def next_step(self) -> PlanStep | None:
        for s in self.steps:
            if s.status == "pending":
                return s
        return None


PLAN_PROMPT = """Based on the objective and current state, create a penetration testing plan.

Return a JSON array of steps. Each step has:
- "tool": tool name from available tools
- "args": arguments for the tool
- "description": what this step accomplishes

Example:
[
  {"tool": "target_scope_check", "args": {"target": "10.10.10.20"}, "description": "Verify target reachability"},
  {"tool": "service_enumeration", "args": {"target": "10.10.10.20", "profile": "basic"}, "description": "Identify open services"}
]

Return ONLY the JSON array. No other text."""


async def generate_plan(
    llm_client,
    objective: str,
    state_summary: str,
    tools_summary: str,
) -> AttackPlan | None:
    """Ask LLM to generate an attack plan."""

    messages = [
        {"role": "system", "content": f"You are a penetration testing planner.\n\n{tools_summary}"},
        {"role": "system", "content": f"CURRENT STATE:\n{state_summary}"},
        {"role": "user", "content": f"Create a plan for: {objective}\n\n{PLAN_PROMPT}"},
    ]

    try:
        response = await llm_client.chat(messages=messages, max_tokens=1024)
        # content may be None (model returned only tool_calls or an empty body)
        # or the key may be missing — coerce to a safe string.
        content = (response.get("content") or "").strip()
        if not content:
            logger.error("plan_generation_empty_content")
            return None

        # Strip a markdown code fence if the model wrapped the JSON.
        if content.startswith("```"):
            import re as _re
            fence = _re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, _re.DOTALL)
            if fence:
                content = fence.group(1).strip()

        # Parse JSON
        if content.startswith("["):
            steps_data = json.loads(content)
        else:
            # Extract the first JSON array from surrounding prose.
            import re
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                steps_data = json.loads(match.group(0))
            else:
                logger.error(f"Cannot parse plan: {content[:200]}")
                return None

        # Some models wrap the array as {"steps": [...]} / {"plan": [...]}.
        if isinstance(steps_data, dict):
            steps_data = steps_data.get("steps") or steps_data.get("plan") or []
        if not isinstance(steps_data, list):
            logger.error("plan_steps_not_a_list", extra={"type": type(steps_data).__name__})
            return None

        plan = AttackPlan(objective=objective)
        dropped = 0
        for i, step in enumerate(steps_data, 1):
            # Skip malformed step entries individually rather than discarding
            # the whole plan.
            if not isinstance(step, dict):
                dropped += 1
                continue
            tool_name = step.get("tool", "")
            if tool_name not in TOOL_REGISTRY:
                logger.warning("plan_dropping_unknown_tool", extra={"tool": tool_name})
                dropped += 1
                continue
            # args must be a dict; coerce anything else so summary()/json.dumps
            # downstream cannot crash on None/list/str.
            args = step.get("args", {})
            if not isinstance(args, dict):
                args = {}
            plan.steps.append(PlanStep(
                step=i,
                tool=tool_name,
                description=step.get("description", ""),
                arguments=args,
            ))

        if dropped:
            logger.info("plan_steps_dropped", extra={"dropped": dropped,
                                                     "kept": len(plan.steps)})
        if plan.steps:
            return plan
        return None

    except (KeyError, TypeError, AttributeError, ValueError, json.JSONDecodeError) as e:
        logger.error(f"Plan generation failed: {type(e).__name__}: {e}")
        return None
