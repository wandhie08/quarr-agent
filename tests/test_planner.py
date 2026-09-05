"""Unit tests for the attack planner (quarr/core/planner.py).

The planner turns an LLM response into an executable, human-approvable plan.
For professional use it must be ROBUST to the messy output real (esp. local)
models produce: null content, markdown fences, dict-wrapped arrays, non-dict
steps, unknown tool names, and non-dict args. These tests lock down both the
happy path and every hardened failure mode.
"""

import pytest

from quarr.core.planner import AttackPlan, PlanStep, generate_plan


class _LLM:
    """Minimal scripted client exposing the chat() contract used by the planner."""
    def __init__(self, content):
        self._content = content

    async def chat(self, messages, max_tokens=1024):
        return {"content": self._content}


VALID_PLAN = (
    '[{"tool": "target_scope_check", "args": {"target": "10.10.10.20"}, '
    '"description": "reachability"}, '
    '{"tool": "service_enumeration", "args": {"target": "10.10.10.20", "profile": "basic"}, '
    '"description": "enumerate"}]'
)


# =========================================================================== #
# AttackPlan / PlanStep behavior
# =========================================================================== #

@pytest.mark.unit
class TestAttackPlanModel:
    def test_summary_lists_steps_with_icons(self):
        plan = AttackPlan(objective="own the box", steps=[
            PlanStep(step=1, tool="service_enumeration", description="enum",
                     arguments={"target": "x"}, status="done"),
            PlanStep(step=2, tool="sqli_scan", description="sqli", arguments={"target": "x"}),
        ])
        text = plan.summary()
        assert "ATTACK PLAN" in text
        assert "own the box" in text
        assert "✅" in text and "⬜" in text
        assert "service_enumeration(target=x)" in text

    def test_next_step_returns_first_pending(self):
        plan = AttackPlan(objective="o", steps=[
            PlanStep(step=1, tool="a", description="", status="done"),
            PlanStep(step=2, tool="b", description="", status="pending"),
        ])
        assert plan.next_step().step == 2

    def test_next_step_none_when_all_processed(self):
        plan = AttackPlan(objective="o", steps=[
            PlanStep(step=1, tool="a", description="", status="done"),
        ])
        assert plan.next_step() is None

    def test_summary_tolerates_non_dict_arguments(self):
        # Defense-in-depth: summary() is called outside generate_plan's guard.
        plan = AttackPlan(objective="o", steps=[
            PlanStep(step=1, tool="a", description="d", arguments=None),
        ])
        assert "ATTACK PLAN" in plan.summary()  # must not raise


# =========================================================================== #
# generate_plan — happy path
# =========================================================================== #

@pytest.mark.unit
class TestGeneratePlanHappyPath:
    async def test_parses_valid_json_array(self):
        plan = await generate_plan(_LLM(VALID_PLAN), "obj", "state", "tools")
        assert plan is not None
        assert [s.tool for s in plan.steps] == ["target_scope_check", "service_enumeration"]
        assert plan.steps[0].arguments == {"target": "10.10.10.20"}

    async def test_extracts_array_from_surrounding_prose(self):
        content = f"Sure, here is the plan:\n{VALID_PLAN}\nExecute carefully."
        plan = await generate_plan(_LLM(content), "obj", "s", "t")
        assert plan is not None and len(plan.steps) == 2

    async def test_strips_markdown_code_fence(self):
        content = f"```json\n{VALID_PLAN}\n```"
        plan = await generate_plan(_LLM(content), "obj", "s", "t")
        assert plan is not None and len(plan.steps) == 2

    async def test_unwraps_dict_wrapped_steps(self):
        content = '{"steps": [{"tool": "target_scope_check", "args": {"target": "x"}}]}'
        plan = await generate_plan(_LLM(content), "obj", "s", "t")
        assert plan is not None and plan.steps[0].tool == "target_scope_check"


# =========================================================================== #
# generate_plan — hardened failure modes (regressions)
# =========================================================================== #

@pytest.mark.unit
class TestGeneratePlanRobustness:
    async def test_null_content_returns_none(self):
        assert await generate_plan(_LLM(None), "obj", "s", "t") is None

    async def test_empty_content_returns_none(self):
        assert await generate_plan(_LLM("   "), "obj", "s", "t") is None

    async def test_no_json_array_returns_none(self):
        assert await generate_plan(_LLM("I cannot help with that."), "obj", "s", "t") is None

    async def test_scalar_json_returns_none(self):
        assert await generate_plan(_LLM("42"), "obj", "s", "t") is None

    async def test_unknown_tools_only_returns_none(self):
        content = '[{"tool": "totally_made_up_tool", "args": {}}]'
        assert await generate_plan(_LLM(content), "obj", "s", "t") is None

    async def test_non_dict_steps_are_skipped_not_fatal(self):
        # A mix of a junk string step and one valid dict step → keep the valid one.
        content = '["do the scan", {"tool": "target_scope_check", "args": {"target": "x"}}]'
        plan = await generate_plan(_LLM(content), "obj", "s", "t")
        assert plan is not None
        assert len(plan.steps) == 1 and plan.steps[0].tool == "target_scope_check"

    async def test_non_dict_args_coerced_to_empty(self):
        content = '[{"tool": "target_scope_check", "args": null, "description": "d"}]'
        plan = await generate_plan(_LLM(content), "obj", "s", "t")
        assert plan is not None
        assert plan.steps[0].arguments == {}
        # And the resulting plan renders without raising.
        assert "ATTACK PLAN" in plan.summary()

    async def test_known_tool_kept_unknown_dropped(self):
        content = ('[{"tool": "target_scope_check", "args": {"target": "x"}}, '
                   '{"tool": "made_up", "args": {}}]')
        plan = await generate_plan(_LLM(content), "obj", "s", "t")
        assert plan is not None
        assert [s.tool for s in plan.steps] == ["target_scope_check"]
