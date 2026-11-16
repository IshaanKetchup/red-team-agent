import asyncio
import json
import logging
import os
import shlex
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from settings import (
    LLM_MAX_TURNS,
    MCP_SERVER_PATH,
    PROJECT_ROOT,
)

from llm.providers import generate_response
from llm.agent import (
    READ_ONLY_COMMANDS,
    build_read_command,
    validate_tool_arguments,
)

logger = logging.getLogger(__name__)

MAX_TOOL_RESULT_CHARS = 6000


def _result_text(result):
    """Convert MCP content into readable text."""
    parts = []

    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        else:
            parts.append(str(item))

    output = "\n".join(parts)

    if getattr(result, "isError", False):
        output = "TOOL EXECUTION ERROR:\n" + output

    try:
        return json.dumps(
            json.loads(output),
            indent=2,
        )
    except (json.JSONDecodeError, TypeError):
        return output


def _compact_tool_result(tool_name, output):
    """
    Reduce tool output before sending it to the LLM.

    The complete output remains available to the frontend.
    """

    try:
        data = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return output[:MAX_TOOL_RESULT_CHARS]

    # Group inventory only needs names for the LLM to answer
    # questions about which groups exist.
    if tool_name == "get_ad_groups" and isinstance(data, dict):
        groups = data.get("groups", [])

        compact = {
            "total": data.get("total"),
            "returned": data.get("returned"),
            "limit": data.get("limit"),
            "offset": data.get("offset"),
            "has_more": data.get("has_more"),
            "groups": [
                {
                    "name": group.get("name"),
                    "sam_account_name": group.get("sam_account_name"),
                    "object_sid": group.get("object_sid"),
                }
                for group in groups
                if isinstance(group, dict)
            ],
        }

        return json.dumps(compact, indent=2)

    # Bound other tool results as well.
    if len(output) > MAX_TOOL_RESULT_CHARS:
        return (
            output[:MAX_TOOL_RESULT_CHARS]
            + "\n[Tool output shortened for LLM context.]"
        )

    return output


def _server_parameters():
    return StdioServerParameters(
        command=sys.executable,
        args=[str(MCP_SERVER_PATH)],
        cwd=str(PROJECT_ROOT),
        env=os.environ.copy(),
    )


async def _open_session():
    server = _server_parameters()
    return stdio_client(server)


async def _run_step(
    history,
    preferred_provider=None,
    pending_calls=None,
    decision=None,
):
    """
    Advance one agent interaction.

    A tool call is never executed without an explicit approval decision.
    Only one pending call is processed per approval action.
    """

    pending_calls = list(pending_calls or [])

    result_data = {
        "history": history,
        "provider": preferred_provider,
        "pending_calls": pending_calls,
        "assistant_text": "",
        "tool_result": None,
        "status": "complete",
        "error": None,
    }

    async with await _open_session() as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tool_response = await session.list_tools()
            mcp_tools = tool_response.tools

            available_tools = {
                tool.name: tool
                for tool in mcp_tools
            }

            # Process one previously proposed tool call.
            if decision is not None:
                if not pending_calls:
                    result_data["error"] = (
                        "There is no pending tool call to process."
                    )
                    result_data["status"] = "error"
                    return result_data

                call = pending_calls.pop(0)

                name = call["name"]
                arguments = call["arguments"]

                if decision == "approve":
                    tool = available_tools.get(name)

                    if tool is None:
                        full_tool_result = (
                            f"Rejected: '{name}' is not an "
                            "available MCP tool."
                        )

                    elif not validate_tool_arguments(tool, arguments):
                        full_tool_result = (
                            "Rejected: arguments do not match "
                            "the MCP tool schema."
                        )

                    else:
                        try:
                            result = await session.call_tool(
                                name,
                                arguments=arguments,
                            )

                            full_tool_result = _result_text(result)

                        except Exception as error:
                            logger.exception(
                                "MCP tool execution failed: %s",
                                name,
                            )

                            full_tool_result = (
                                f"Tool execution failed: "
                                f"{type(error).__name__}: {error}"
                            )

                elif decision == "decline":
                    full_tool_result = (
                        f"Execution of {name} was declined "
                        "by the operator."
                    )

                else:
                    result_data["error"] = "Invalid approval decision."
                    result_data["status"] = "error"
                    return result_data

                # Keep the complete result for frontend display.
                # Send only the compact result to the LLM.
                llm_tool_result = _compact_tool_result(
                    name,
                    full_tool_result,
                )

                history.append({
                    "role": "tool_result",
                    "call_id": call["call_id"],
                    "provider_call_id": call.get("provider_call_id"),
                    "name": name,
                    "content": llm_tool_result,
                    "display_content": full_tool_result,
                })

                result_data["tool_result"] = {
                    "name": name,
                    "content": full_tool_result,
                    "approved": decision == "approve",
                }

                result_data["pending_calls"] = pending_calls

                # Remaining calls must each receive their own approval.
                if pending_calls:
                    result_data["status"] = "pending_approval"
                    return result_data

            # Continue reasoning after the previous tool result.
            for _ in range(LLM_MAX_TURNS):
                try:
                    response = await asyncio.to_thread(
                        generate_response,
                        history,
                        mcp_tools,
                        result_data["provider"],
                    )

                except Exception as error:
                    logger.exception("LLM provider request failed")

                    result_data["error"] = (
                        f"LLM request failed: "
                        f"{type(error).__name__}: {error}"
                    )
                    result_data["status"] = "error"
                    return result_data

                if result_data["provider"] is None:
                    result_data["provider"] = response.provider

                if response.tool_calls:
                    history.append({
                        "role": "assistant_tool_calls",
                        "content": response.text,
                        "tool_calls": response.tool_calls,
                        "provider_content": response.provider_content,
                    })

                    result_data["assistant_text"] = response.text
                    result_data["pending_calls"] = response.tool_calls
                    result_data["status"] = "pending_approval"

                    return result_data

                if response.text:
                    history.append({
                        "role": "assistant",
                        "content": response.text,
                    })

                result_data["assistant_text"] = response.text
                result_data["status"] = "complete"
                return result_data

            result_data["status"] = "max_turns"
            result_data["assistant_text"] = (
                "Agent stopped: maximum reasoning turns reached."
            )

            history.append({
                "role": "assistant",
                "content": result_data["assistant_text"],
            })

            return result_data


def run_agent_step(
    history,
    preferred_provider=None,
    pending_calls=None,
    decision=None,
):
    """Synchronous wrapper for Streamlit."""
    return asyncio.run(
        _run_step(
            history=history,
            preferred_provider=preferred_provider,
            pending_calls=pending_calls,
            decision=decision,
        )
    )


async def _run_readonly_command(prompt):
    """Execute an explicit read-only command without an LLM request."""

    try:
        tokens = shlex.split(prompt)
    except ValueError as error:
        return {
            "handled": True,
            "error": f"Command parsing error: {error}",
        }

    if not tokens:
        return {"handled": True, "result": ""}

    command = tokens[0].lower()

    if command == "/help":
        return {
            "handled": True,
            "result": """
Read-only commands:

/summary [recent_limit]
/findings [--status ACTIVE] [--severity HIGH] [--host IP]
          [--rule-id RULE] [--limit N] [--offset N]
/history [limit]
/hosts [limit]
/services [--host-ip IP] [--limit N]
/detail FINDING_ID
/compare OLDER_RUN_ID NEWER_RUN_ID [LIMIT]
/ad-groups [--search TEXT] [--limit N] [--offset N]
/ad-group-members "GROUP NAME" [--include-nested true|false]
                  [--limit N] [--offset N]
/ad-user-groups USER [--include-nested true|false]
                [--limit N] [--offset N]
/ad-paths [--user USER] [--group GROUP]
           [--limit N] [--offset N]
""",
        }

    if command not in READ_ONLY_COMMANDS:
        return {
            "handled": True,
            "error": f"Unknown local command: {command}. Use /help.",
        }

    try:
        arguments = build_read_command(command, tokens[1:])
    except ValueError as error:
        return {
            "handled": True,
            "error": f"Invalid command: {error}",
        }

    tool_name = READ_ONLY_COMMANDS[command]

    async with await _open_session() as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tool_response = await session.list_tools()

            available_tools = {
                tool.name: tool
                for tool in tool_response.tools
            }

            tool = available_tools.get(tool_name)

            if tool is None:
                return {
                    "handled": True,
                    "error": f"MCP tool is unavailable: {tool_name}",
                }

            if not validate_tool_arguments(tool, arguments):
                return {
                    "handled": True,
                    "error": "Arguments do not match the MCP tool schema.",
                }

            result = await session.call_tool(
                tool_name,
                arguments=arguments,
            )

            return {
                "handled": True,
                "tool": tool_name,
                "result": _result_text(result),
            }


def run_readonly_command(prompt):
    return asyncio.run(_run_readonly_command(prompt))
