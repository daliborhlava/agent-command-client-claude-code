#!/usr/bin/env python3
"""Send Claude Code hook events to the monitoring server."""

import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

SERVER_URL = os.environ.get("AGENT_COMMAND_URL", "http://localhost:8787")
TIMEOUT = 5
PERMISSION_TIMEOUT = 300
MAX_TRANSCRIPT_LINES = 100
CLIENT_VERSION = "1.2.6"


def read_transcript(transcript_path: str | None) -> list[dict]:
    """Read recent messages from transcript JSONL file."""
    if not transcript_path:
        return []

    path = Path(transcript_path)
    if not path.exists():
        return []

    messages = []
    try:
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entry_type = entry.get("type")
                    # Skip non-message entries
                    if entry_type not in ("user", "assistant"):
                        continue
                    messages.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []

    return messages[-MAX_TRANSCRIPT_LINES:]


def extract_text_content(content) -> str | None:
    """Extract text content from message content."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    texts.append(block.get("text", ""))
            elif isinstance(block, str):
                texts.append(block)
        return "\n".join(texts) if texts else None
    return None


def extract_thinking_content(content) -> str | None:
    """Extract thinking content from message content blocks."""
    if not isinstance(content, list):
        return None
    parts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "thinking":
            thinking = block.get("thinking", "")
            if thinking:
                parts.append(thinking)
    return "\n".join(parts) if parts else None


def extract_tool_results(entries: list[dict]) -> dict[str, dict]:
    """Extract tool_result text and error status keyed by tool_use_id from user entries."""
    results = {}
    for entry in entries:
        if entry.get("type") != "user":
            continue
        content = entry.get("message", {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                tool_use_id = block.get("tool_use_id")
                if not tool_use_id:
                    continue
                result_content = block.get("content")
                text = extract_text_content(result_content)
                if text:
                    results[tool_use_id] = {
                        "text": text[:2000],
                        "is_error": bool(block.get("is_error")),
                    }
    return results


def simplify_transcript(entries: list[dict]) -> list[dict]:
    """Simplify transcript entries for sending to server."""
    simplified = []
    tool_results = extract_tool_results(entries)

    for entry in entries:
        entry_type = entry.get("type")
        if entry_type not in ("user", "assistant"):
            continue

        # Get the message object
        message = entry.get("message", {})
        role = message.get("role", entry_type)
        content = message.get("content")
        timestamp = entry.get("timestamp")

        # Extract text and thinking content
        text = extract_text_content(content)
        thinking = extract_thinking_content(content)

        # Skip whitespace-only text (e.g. '\n\n' preamble entries)
        if text and not text.strip():
            text = None

        # Also extract tool_use from assistant messages
        tool_uses = []
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    tool_uses.append({
                        "tool_name": block.get("name"),
                        "tool_input": block.get("input"),
                        "tool_use_id": block.get("id"),
                    })

        # Add message entry if text or thinking present
        if text or thinking:
            msg = {
                "type": "message",
                "role": role,
                "uuid": entry.get("uuid"),
                "timestamp": timestamp,
            }
            if text:
                msg["text"] = text[:2000]
            if thinking:
                msg["thinking"] = thinking[:5000]
            simplified.append(msg)

        # Add tool uses as separate entries
        for tool in tool_uses:
            tool_entry = {
                "type": "tool_use",
                "role": "assistant",
                "tool_name": tool["tool_name"],
                "tool_input": tool["tool_input"],
                "tool_use_id": tool["tool_use_id"],
                "uuid": entry.get("uuid"),
                "timestamp": timestamp,
            }
            # Attach tool result if available
            result = tool_results.get(tool["tool_use_id"])
            if result:
                tool_entry["tool_response"] = result["text"]
                if result["is_error"]:
                    tool_entry["is_error"] = True
            simplified.append(tool_entry)

    return simplified


def get_tmux_session() -> str | None:
    """Get current tmux session name if running inside tmux via claude-wrapper."""
    return os.environ.get("CLAUDE_TMUX_SESSION") or None


def get_host_info() -> dict:
    """Get host identification info."""
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
    }


def extract_usage_from_transcript(entries: list[dict]) -> dict:
    """Extract cumulative token usage from transcript entries."""
    total_input = 0
    total_output = 0
    total_cache_read = 0
    total_cache_create = 0

    for entry in entries:
        if entry.get("type") != "assistant":
            continue
        message = entry.get("message", {})
        usage = message.get("usage", {})
        total_input += usage.get("input_tokens", 0)
        total_output += usage.get("output_tokens", 0)
        total_cache_read += usage.get("cache_read_input_tokens", 0)
        total_cache_create += usage.get("cache_creation_input_tokens", 0)

    if total_input == 0 and total_output == 0:
        return {}

    return {
        "input_tokens": total_input,
        "output_tokens": total_output,
        "cache_read_tokens": total_cache_read,
        "cache_create_tokens": total_cache_create,
    }


def _send_pre_event(data: dict) -> None:
    """Send a PreToolUse event with transcript to /api/events before long-polling.

    When AskUserQuestion/ExitPlanMode are intercepted, the normal event path is
    skipped.  This helper sends the regular event (with transcript) first so that
    any assistant text preceding the tool call is visible on the dashboard.
    """
    host_info = get_host_info()
    event = {
        "session_id": data.get("session_id", "unknown"),
        "monitor_id": os.environ.get("AGENT_MONITOR_ID"),
        "tmux_session": get_tmux_session(),
        "hook_event": "PreToolUse",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": data.get("tool_name"),
        "tool_input": data.get("tool_input"),
        "tool_use_id": data.get("tool_use_id"),
        "cwd": data.get("cwd"),
        "hostname": host_info["hostname"],
        "platform": host_info["platform"],
        "user": host_info["user"],
        "model": data.get("model"),
        "permission_mode": data.get("permission_mode"),
        "extra": {},
        "transcript": [],
    }

    transcript_path = data.get("transcript_path")
    if transcript_path:
        path = Path(transcript_path)
        if path.exists():
            entries = read_transcript(transcript_path)
            event["transcript"] = simplify_transcript(entries)
            usage = extract_usage_from_transcript(entries)
            if usage:
                event["extra"]["usage"] = usage

    try:
        payload = json.dumps(event).encode("utf-8")
        req = Request(
            f"{SERVER_URL}/api/events",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=TIMEOUT) as resp:
            resp.read()
    except Exception:
        pass


def send_permission_request(data: dict) -> None:
    """Send permission request via long-poll endpoint and print decision to stdout."""
    session_id = data.get("session_id", "unknown")
    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input")

    ask_response = json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "ask"},
        }
    })

    payload = json.dumps({
        "tool_name": tool_name,
        "tool_input": tool_input,
    }).encode("utf-8")

    request = Request(
        f"{SERVER_URL}/api/agents/{session_id}/permission",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=PERMISSION_TIMEOUT) as response:
            result = json.loads(response.read().decode("utf-8"))
            print(json.dumps(result))
    except Exception:
        print(ask_response)


def send_question_request(data: dict) -> None:
    """Send AskUserQuestion via long-poll endpoint and print response to stdout."""
    session_id = data.get("session_id", "unknown")
    tool_input = data.get("tool_input", {})

    allow_response = json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }
    })

    payload = json.dumps({
        "tool_input": tool_input,
    }).encode("utf-8")

    request = Request(
        f"{SERVER_URL}/api/agents/{session_id}/question",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=PERMISSION_TIMEOUT) as response:
            result = json.loads(response.read().decode("utf-8"))
            print(json.dumps(result))
    except Exception:
        print(allow_response)


def _notify_plan(data: dict) -> None:
    """Fire-and-forget notification to server that ExitPlanMode was called.

    Does NOT print any hookSpecificOutput — the native CLI prompt handles approval.
    """
    session_id = data.get("session_id", "unknown")
    tool_input = data.get("tool_input", {})

    payload = json.dumps({
        "tool_input": tool_input,
    }).encode("utf-8")

    request = Request(
        f"{SERVER_URL}/api/agents/{session_id}/plan",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            response.read()
    except Exception:
        pass


def send_event(data: dict) -> None:
    hook_event = data.get("hook_event_name")

    # PermissionRequest uses a dedicated long-poll endpoint
    # Skip tools already handled by their own PreToolUse interceptors
    if hook_event == "PermissionRequest":
        tool_name = data.get("tool_name")
        if tool_name == "AskUserQuestion":
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "allow"},
                }
            }))
            return
        if tool_name == "ExitPlanMode":
            # Let the native CLI plan approval menu show
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "ask"},
                }
            }))
            return
        send_permission_request(data)
        return

    # PreToolUse intercepts for AskUserQuestion and ExitPlanMode
    if hook_event == "PreToolUse":
        tool_name = data.get("tool_name")
        if tool_name == "AskUserQuestion":
            _send_pre_event(data)
            send_question_request(data)
            return
        if tool_name == "ExitPlanMode":
            _send_pre_event(data)
            _notify_plan(data)
            return

    host_info = get_host_info()
    tmux_session = get_tmux_session()

    event = {
        "session_id": data.get("session_id", "unknown"),
        "monitor_id": os.environ.get("AGENT_MONITOR_ID"),
        "tmux_session": tmux_session,
        "hook_event": hook_event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": data.get("tool_name"),
        "tool_input": data.get("tool_input"),
        "tool_response": data.get("tool_response"),
        "tool_use_id": data.get("tool_use_id"),
        "cwd": data.get("cwd"),
        "notification_type": data.get("notification_type"),
        "hostname": host_info["hostname"],
        "platform": host_info["platform"],
        "user": host_info["user"],
        "model": data.get("model"),
        "permission_mode": data.get("permission_mode"),
        "extra": {},
        "transcript": [],
    }

    if hook_event == "PostToolUseFailure":
        event["error_message"] = data.get("error") or data.get("error_message")
        event["is_interrupt"] = data.get("is_interrupt", False)

    if hook_event in ("SubagentStart", "SubagentStop"):
        event["subagent_id"] = data.get("subagent_id") or data.get("agent_id")
        event["subagent_task"] = data.get("task") or data.get("description")
        event["subagent_type"] = data.get("agent_type")

    if hook_event in ("Stop", "SubagentStop"):
        event["stop_hook_active"] = data.get("stop_hook_active", False)

    if hook_event == "UserPromptSubmit":
        event["prompt"] = data.get("prompt")

    if hook_event == "SessionStart":
        event["client_version"] = CLIENT_VERSION

    if "source" in data:
        event["extra"]["source"] = data["source"]

    if "reason" in data:
        event["extra"]["reason"] = data["reason"]

    if hook_event in ("Stop", "SessionStart", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit"):
        transcript_path = data.get("transcript_path")
        if transcript_path:
            path = Path(transcript_path)
            if path.exists():
                entries = read_transcript(transcript_path)
                simplified = simplify_transcript(entries)
                event["transcript"] = simplified

                usage = extract_usage_from_transcript(entries)
                if usage:
                    event["extra"]["usage"] = usage

                # Extract model from transcript if not already set
                if not event.get("model"):
                    for entry in reversed(entries):
                        if entry.get("type") == "assistant":
                            model = entry.get("message", {}).get("model")
                            if model:
                                event["model"] = model
                                break

                print(f"[agent-command] {hook_event}: {len(simplified)} entries", file=sys.stderr)

    payload = json.dumps(event).encode("utf-8")
    request = Request(
        f"{SERVER_URL}/api/events",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            response.read()
    except URLError:
        pass  # Silent fail - don't break Claude Code workflow


def main() -> None:
    try:
        data = json.load(sys.stdin)
        send_event(data)
    except json.JSONDecodeError:
        pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
