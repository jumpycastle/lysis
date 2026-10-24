"""A fake Anthropic client for offline tests: returns canned tool calls per pass."""
from __future__ import annotations

import itertools
from types import SimpleNamespace as NS

_ids = itertools.count(1)


def _tool_use(name: str, inp: dict):
    return NS(type="tool_use", id=f"toolu_{next(_ids)}", name=name, input=inp,
              model_dump=lambda exclude_none=True: {"type": "tool_use", "id": "x", "name": name, "input": inp})


class FakeMessages:
    def __init__(self, canned: dict, agent_script: list[tuple[str, dict]] | None = None):
        self.canned = canned
        self.agent_script = list(agent_script or [])
        self.calls: list[dict] = []
        self.text_first: set[str] = {"submit_draft"}

    def create(self, **kw):
        self.calls.append(kw)
        assert kw.get("tool_choice", {}).get("type") == "auto", "forced tool_choice is rejected by 5.5 models"
        tools = kw.get("tools", [])
        usage = NS(input_tokens=1000, output_tokens=200, cache_read_input_tokens=800,
                   cache_creation_input_tokens=0)
        if len(tools) == 1:
            name = tools[0]["name"]
            if name in self.text_first:  # simulate the model answering in prose first
                self.text_first.discard(name)
                txt = NS(type="text", text="Here is my analysis...",
                         model_dump=lambda exclude_none=True: {"type": "text", "text": "Here is my analysis..."})
                return NS(content=[txt], usage=usage, stop_reason="end_turn")
            content = [_tool_use(name, self.canned.get(name, {}))]
        else:  # agent loop: follow the script, then submit
            if self.agent_script:
                name, inp = self.agent_script.pop(0)
            else:
                name, inp = "submit_verification", self.canned["submit_verification"]
            content = [_tool_use(name, inp)]
        return NS(content=content, usage=usage, stop_reason="tool_use")


class FakeClient:
    def __init__(self, canned: dict, agent_script=None):
        self.messages = FakeMessages(canned, agent_script)
