"""Thin wrapper over the Anthropic Messages API.

- Structured output via a forced tool call, validated with pydantic, one repair retry.
- Prompt caching: the shared prefix (policy + standards + gates, then the artifacts) is marked
  with cache_control so every pass after the first reads it from cache (per model).
- A small agent loop for the code-verification pass (read-only tools + a submit tool).
- Token usage recorded per pass.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from .schema import tool_schema

CACHE = {"type": "ephemeral"}


@dataclass
class PassUsage:
    pass_name: str
    model: str
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    seconds: float = 0.0


@dataclass
class Ledger:
    passes: list[PassUsage] = field(default_factory=list)

    def get(self, pass_name: str, model: str) -> PassUsage:
        for p in self.passes:
            if p.pass_name == pass_name:
                return p
        p = PassUsage(pass_name, model)
        self.passes.append(p)
        return p

    def totals(self) -> dict:
        keys = ("calls", "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")
        return {k: sum(getattr(p, k) for p in self.passes) for k in keys}


def with_cache_marker(blocks: list[dict]) -> list[dict]:
    """Return a copy of blocks with cache_control set on the last block."""
    if not blocks:
        return blocks
    out = [dict(b) for b in blocks]
    out[-1]["cache_control"] = CACHE
    return out


class LLM:
    def __init__(self, client: Any = None, max_tokens: int = 16000, ledger: Ledger | None = None):
        if client is None:
            import anthropic
            client = anthropic.Anthropic()
        self.client = client
        self.max_tokens = max_tokens
        self.ledger = ledger or Ledger()

    # ---------------------------------------------------------------- low level
    def _create(self, pass_name: str, **kw) -> Any:
        u = self.ledger.get(pass_name, kw["model"])
        t0 = time.time()
        last_err = None
        for attempt in range(4):
            try:
                if hasattr(self.client.messages, "stream"):
                    with self.client.messages.stream(**kw) as s:
                        msg = s.get_final_message()
                else:
                    msg = self.client.messages.create(**kw)
                break
            except Exception as e:  # retry transient API errors
                last_err = e
                status = getattr(e, "status_code", None)
                if status is not None and status < 500 and status != 429:
                    raise
                time.sleep(2 ** attempt * 3)
        else:
            raise last_err  # type: ignore[misc]
        u.calls += 1
        u.seconds += time.time() - t0
        usage = getattr(msg, "usage", None)
        if usage is not None:
            u.input_tokens += getattr(usage, "input_tokens", 0) or 0
            u.output_tokens += getattr(usage, "output_tokens", 0) or 0
            u.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
            u.cache_write_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
        return msg

    # ---------------------------------------------------------------- structured
    # Newer models reject forced tool_choice ("tool"/"any"), so we offer the tool with
    # tool_choice "auto", tell the model to call it, and re-prompt if it answers in text.
    def _create_with_room(self, pass_name: str, **kw) -> Any:
        """Call the API; if the reply was cut off by max_tokens, retry once with double room."""
        msg = self._create(pass_name, **kw)
        if getattr(msg, "stop_reason", None) == "max_tokens" and kw["max_tokens"] < 64000:
            kw = {**kw, "max_tokens": min(kw["max_tokens"] * 2, 64000)}
            msg = self._create(pass_name, **kw)
        if getattr(msg, "stop_reason", None) == "max_tokens":
            raise RuntimeError(f"{pass_name}: output hit max_tokens ({kw['max_tokens']}); "
                               "raise max_tokens in the profile")
        return msg

    def structured(self, *, pass_name: str, model: str, system: list[dict], content: list[dict],
                   tool_name: str, out_model: type[BaseModel], description: str = "") -> BaseModel:
        tool = {"name": tool_name,
                "description": (description or f"Submit the {pass_name} result.")
                + " You must call this tool exactly once with the complete result.",
                "input_schema": tool_schema(out_model)}
        messages: list[dict] = [{"role": "user", "content": content}]
        last_err = ""
        for attempt in range(3):
            msg = self._create_with_room(pass_name, model=model, max_tokens=self.max_tokens,
                                         system=system, messages=messages, tools=[tool],
                                         tool_choice={"type": "auto"})
            messages.append({"role": "assistant", "content": [_block_to_dict(b) for b in msg.content]})
            tu = next((b for b in msg.content
                       if getattr(b, "type", "") == "tool_use" and b.name == tool_name), None)
            if tu is None:
                last_err = "model replied without calling the tool"
                messages.append({"role": "user", "content":
                                 f"Do not reply in text. Call the `{tool_name}` tool now with the complete result."})
                continue
            try:
                return out_model.model_validate(tu.input)
            except ValidationError as e:
                last_err = str(e)
                messages.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": tu.id, "is_error": True,
                     "content": f"Schema validation failed; fix and call `{tool_name}` again:\n{e}"}]})
        raise RuntimeError(f"{pass_name}: no valid `{tool_name}` call after 3 attempts ({last_err[:500]})")

    # ---------------------------------------------------------------- agent loop
    def agent(self, *, pass_name: str, model: str, system: list[dict], content: list[dict],
              tools: list[dict], handlers: dict[str, Callable[[dict], str]],
              submit_name: str, submit_model: type[BaseModel], max_tool_calls: int = 40,
              log: Callable[[str], None] | None = None) -> BaseModel:
        submit_tool = {"name": submit_name,
                       "description": "Submit final results. Call exactly once when done.",
                       "input_schema": tool_schema(submit_model)}
        all_tools = tools + [submit_tool]
        messages: list[dict] = [{"role": "user", "content": content}]
        calls, turns = 0, 0
        while True:
            turns += 1
            if turns > max_tool_calls + 8:
                if log:
                    log("  verification did not submit; continuing without it")
                return submit_model()
            msg = self._create_with_room(pass_name, model=model, max_tokens=self.max_tokens,
                                         system=system, messages=messages, tools=all_tools,
                                         tool_choice={"type": "auto"})
            messages.append({"role": "assistant", "content": [_block_to_dict(b) for b in msg.content]})
            results = []
            for b in msg.content:
                if getattr(b, "type", "") != "tool_use":
                    continue
                if b.name == submit_name:
                    try:
                        return submit_model.model_validate(b.input)
                    except ValidationError as e:
                        results.append({"type": "tool_result", "tool_use_id": b.id, "is_error": True,
                                        "content": f"Schema validation failed; fix and resubmit:\n{e}"})
                        continue
                if calls >= max_tool_calls:
                    results.append({"type": "tool_result", "tool_use_id": b.id, "is_error": True,
                                    "content": f"Tool budget exhausted. Call `{submit_name}` now."})
                    continue
                calls += 1
                fn = handlers.get(b.name)
                try:
                    out = fn(b.input) if fn else f"unknown tool {b.name}"
                except Exception as e:
                    out = f"error: {e}"
                if log:
                    log(f"  [{calls}/{max_tool_calls}] {b.name} {json.dumps(b.input)[:120]}")
                remaining = max_tool_calls - calls
                if remaining <= 3:
                    out += f"\n\n[{remaining} tool calls left; then you must call `{submit_name}`]"
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": out})
            if not results:
                messages.append({"role": "user", "content":
                                 f"Continue using the tools, or call `{submit_name}` with your results."})
            else:
                messages.append({"role": "user", "content": results})


def _block_to_dict(b: Any) -> dict:
    if isinstance(b, dict):
        return b
    if hasattr(b, "model_dump"):
        d = b.model_dump(exclude_none=True)
        if d.get("type") == "text" and not d.get("citations"):
            d.pop("citations", None)
        return d
    return {"type": "text", "text": str(b)}
