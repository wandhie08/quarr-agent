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
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from quarr.tools.registry import TOOL_REGISTRY, get_tools_summary

logger = logging.getLogger("quarr.planner")


@dataclass
class PlanStep:
    step: int
    tool: str
    description: str
    arguments: Dict = field(default_factory=dict)
    status: str = "pending"  # pending, running, done, skipped, failed


@dataclass
class AttackPlan:
    objective: str
    steps: List[PlanStep] = field(default_factory=list)
    current_step: int = 0
    status: str = "draft"  # draft, approved, running, completed

    def summary(self) -> str:
        lines = [
            f"📋 ATTACK PLAN",
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
            args_str = ", ".join(f"{k}={v}" for k, v in s.arguments.items())
            lines.append(f"  {icon} {s.step}. {s.tool}({args_str})")
            lines.append(f"     {s.description}")
        return "\n".join(lines)

    def next_step(self) -> Optional[PlanStep]:
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
) -> Optional[AttackPlan]:
    """Ask LLM to generate an attack plan."""

    messages = [
        {"role": "system", "content": f"You are a penetration testing planner.\n\n{tools_summary}"},
        {"role": "system", "content": f"CURRENT STATE:\n{state_summary}"},
        {"role": "user", "content": f"Create a plan for: {objective}\n\n{PLAN_PROMPT}"},
    ]

    try:
        response = await llm_client.chat(messages=messages, max_tokens=1024)
        content = response["content"].strip()

        # Parse JSON
        if content.startswith("["):
            steps_data = json.loads(content)
        else:
            # Extract JSON from text
            import re
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                steps_data = json.loads(match.group(0))
            else:
                logger.error(f"Cannot parse plan: {content[:200]}")
                return None

        plan = AttackPlan(objective=objective)
        for i, step in enumerate(steps_data, 1):
            tool_name = step.get("tool", "")
            if tool_name in TOOL_REGISTRY:
                plan.steps.append(PlanStep(
                    step=i,
                    tool=tool_name,
                    description=step.get("description", ""),
                    arguments=step.get("args", {}),
                ))

        if plan.steps:
            return plan
        return None

    except Exception as e:
        logger.error(f"Plan generation failed: {e}")
        return None
