
import asyncio
import json
import logging
import os
import sys
import shlex

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from settings import (
    LLM_MAX_TURNS,
    MCP_SERVER_PATH,
    PROJECT_ROOT,
)

from llm.providers import generate_response


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)

logger = logging.getLogger("red-team-agent")

MAX_TOOL_RESULT_CHARS = 30000


def format_tool_result(result):
    """Convert MCP content into bounded text for the LLM."""
    parts = []

    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        else:
            parts.append(str(item))

    output = "\n".join(parts)

    if getattr(result, "isError", False):
        output = "TOOL EXECUTION ERROR:\n" + output

    if len(output) > MAX_TOOL_RESULT_CHARS:
        output = (
            output[:MAX_TOOL_RESULT_CHARS]
            + "\n[Output truncated before sending to the LLM.]"
        )

    return output


def validate_tool_arguments(tool, arguments):
    """Reject arguments that do not match the MCP tool schema."""
    if not isinstance(arguments, dict):
        return False

    schema = tool.inputSchema or {}
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    if not isinstance(properties, dict):
        return False

    if not all(key in properties for key in arguments):
        return False

    if not all(key in arguments for key in required):
        return False

    return True


def approve_tool_call(name, arguments):
    """Require interactive approval before every MCP operation."""
    print("\nProposed tool call")
    print("Tool:", name)
    print("Arguments:", json.dumps(arguments, indent=2))

    answer = input(
        "\nExecute this tool? Type YES to approve: "
    ).strip()

    return answer == "YES"

def read_prompt():
    """Read single-line or explicitly multiline user input."""
    first_line = input("\nYou: ").strip()

    if first_line == "/multi":
        print("Enter your prompt. Type /end on a separate line to submit.")
        lines = []

        while True:
            line = input("... ")

            if line.strip() == "/end":
                break

            lines.append(line)

        return "\n".join(lines).strip()

    return first_line


READ_ONLY_COMMANDS = {
    "/summary": "get_findings_summary",
    "/findings": "get_findings",
    "/history": "get_scan_history",
    "/hosts": "get_host_inventory",
    "/services": "get_service_inventory",
    "/detail": "get_finding_details",
    "/compare": "compare_scan_runs",
    "/ad-groups": "get_ad_groups",
    "/ad-group-members": "get_ad_group_members",
    "/ad-user-groups": "get_ad_user_groups",
    "/ad-paths": "get_ad_membership_paths",
}


def parse_command_arguments(tokens, allowed_options):
    """Parse --option value pairs and reject unknown options."""
    arguments = {}
    index = 0

    while index < len(tokens):
        token = tokens[index]

        if not token.startswith("--"):
            raise ValueError(f"Unexpected argument: {token}")

        key = token[2:].replace("-", "_")

        if key not in allowed_options:
            raise ValueError(f"Unknown option: {token}")

        if key in arguments:
            raise ValueError(f"Duplicate option: {token}")

        index += 1

        if index >= len(tokens):
            raise ValueError(f"Missing value for --{key.replace('_', '-')}")

        value = tokens[index]

        if value.startswith("--"):
            raise ValueError(f"Missing value for --{key.replace('_', '-')}")

        arguments[key] = value
        index += 1

    for key in ("limit", "offset", "recent_limit"):
        if key in arguments:
            try:
                arguments[key] = int(arguments[key])
            except ValueError:
                raise ValueError(f"--{key.replace('_', '-')} must be an integer")

    return arguments


def build_read_command(command, tokens):
    """Translate local commands into MCP tool arguments."""

    if command in ("/summary", "/history", "/hosts"):
        if len(tokens) > 1:
            raise ValueError(f"Too many arguments for {command}")

        if not tokens:
            return {}

        try:
            value = int(tokens[0])
        except ValueError:
            raise ValueError("Expected an integer argument")

        if command == "/summary":
            return {"recent_limit": value}

        return {"limit": value}

    if command == "/detail":
        if len(tokens) != 1:
            raise ValueError("Usage: /detail FINDING_ID")

        try:
            finding_id = int(tokens[0])
        except ValueError:
            raise ValueError("Finding ID must be an integer")

        if finding_id <= 0:
            raise ValueError("Finding ID must be positive")

        return {"finding_id": finding_id}

    if command == "/compare":
        if len(tokens) not in (2, 3):
            raise ValueError(
                "Usage: /compare OLDER_RUN_ID NEWER_RUN_ID [LIMIT]"
            )

        try:
            older_run_id = int(tokens[0])
            newer_run_id = int(tokens[1])
            limit = int(tokens[2]) if len(tokens) == 3 else 50
        except ValueError:
            raise ValueError("Scan IDs and limit must be integers")

        if older_run_id <= 0 or newer_run_id <= 0:
            raise ValueError("Scan IDs must be positive")

        if older_run_id == newer_run_id:
            raise ValueError("Scan IDs must be different")

        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100")

        return {
            "older_run_id": older_run_id,
            "newer_run_id": newer_run_id,
            "limit": limit,
        }

    if command == "/findings":
        return parse_command_arguments(
            tokens,
            {
                "status",
                "severity",
                "host",
                "rule_id",
                "limit",
                "offset",
            },
        )

    if command == "/services":
        return parse_command_arguments(
            tokens,
            {"host_ip", "limit"},
        )

    if command == "/ad-groups":
        return parse_command_arguments(
            tokens,
            {"search", "limit", "offset"},
        )

    if command in ("/ad-group-members", "/ad-user-groups"):
        if not tokens or tokens[0].startswith("--"):
            raise ValueError(
                f"Usage: {command} OBJECT [--include-nested true|false] "
                "[--limit N] [--offset N]"
            )

        identifier = tokens[0]
        options = parse_command_arguments(
            tokens[1:],
            {"include_nested", "limit", "offset"},
        )

        if "include_nested" in options:
            value = options["include_nested"].lower()
            if value not in ("true", "false"):
                raise ValueError("--include-nested must be true or false")
            options["include_nested"] = value == "true"

        key = "group" if command == "/ad-group-members" else "user"
        return {key: identifier, **options}

    if command == "/ad-paths":
        return parse_command_arguments(
            tokens,
            {"user", "group", "limit", "offset"},
        )

    return {}


def print_direct_result(name, result):
    """Display read-only MCP results without involving an LLM."""
    print("\n" + "=" * 60)
    print(f"DIRECT MCP RESULT: {name}")
    print("=" * 60)

    output = format_tool_result(result)

    try:
        parsed = json.loads(output)
        output = json.dumps(parsed, indent=2)
    except (json.JSONDecodeError, TypeError):
        pass

    print(output)
    print("=" * 60)


async def handle_local_command(session, prompt, available_tools):
    """
    Execute explicit read-only commands without calling an LLM.

    Returns True when the input was handled as a local command.
    """
    if not prompt.startswith("/"):
        return False

    try:
        tokens = shlex.split(prompt)
    except ValueError as error:
        print(f"Command parsing error: {error}")
        return True

    if not tokens:
        return True

    command = tokens[0].lower()

    if command == "/help":
        print("""
Read-only commands:

  /summary [recent_limit]
  /findings [--status ACTIVE] [--severity HIGH]
            [--host IP] [--rule-id RULE] [--limit N] [--offset N]
  /history [limit]
  /hosts [limit]
  /services [--host-ip IP] [--limit N]
  /detail FINDING_ID
  /compare OLDER_RUN_ID NEWER_RUN_ID [LIMIT]
  /ad-groups [--search TEXT] [--limit N] [--offset N]
  /ad-group-members GROUP [--include-nested true|false] [--limit N]
  /ad-user-groups USER [--include-nested true|false] [--limit N]
  /ad-paths [--user USER] [--group GROUP] [--limit N]

Examples:

  /summary
  /findings --status ACTIVE --severity HIGH
  /findings --host 192.168.56.10 --limit 20
  /history 10
  /hosts
  /services --host-ip 192.168.56.10
  /detail 42
  /compare 12 15
  /compare 12 15 20
  /ad-groups --search admin
  /ad-group-members "Domain Admins"
  /ad-user-groups alice
  /ad-paths --group "Domain Admins"
  /ad-paths --user alice --group "Domain Admins"
""")
        return True

    if command not in READ_ONLY_COMMANDS:
        print(f"Unknown local command: {command}. Use /help.")
        return True

    tool_name = READ_ONLY_COMMANDS[command]

    try:
        arguments = build_read_command(command, tokens[1:])
    except ValueError as error:
        print(f"Invalid command: {error}")
        return True

    tool = available_tools.get(tool_name)

    if tool is None:
        print(f"MCP tool is unavailable: {tool_name}")
        return True

    if not validate_tool_arguments(tool, arguments):
        print("Command arguments do not match the MCP tool schema.")
        return True


    try:
        result = await session.call_tool(
            tool_name,
            arguments=arguments,
        )
        print_direct_result(tool_name, result)

    except Exception as error:
        logger.exception("Direct MCP query failed: %s", tool_name)
        print(
            f"Direct query failed: {type(error).__name__}: {error}"
        )

    return True

async def run_agent():
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(MCP_SERVER_PATH)],
        cwd=str(PROJECT_ROOT),
        env=os.environ.copy(),
    )

    print("Starting Red Team Agent...")
    print("Connecting to MCP server...")

    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tool_response = await session.list_tools()
            mcp_tools = tool_response.tools

            available_tools = {
                tool.name: tool
                for tool in mcp_tools
            }

            print("\nConnected to MCP server.")
            print("Available tools:")

            for tool in mcp_tools:
                print(f" - {tool.name}: {tool.description}")

            print("\nAgent ready. Type 'exit' to quit.")

            while True:
                try:
                    prompt = read_prompt()
                except EOFError:
                    break

                if prompt.lower() in ("exit", "quit"):
                    break

                if not prompt:
                    continue
                
                if await handle_local_command(
                        session,
                        prompt,
                        available_tools,
                ):
                    continue

                history = [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ]

                # Keep one provider for all reasoning/tool rounds
                # belonging to this user prompt.
                active_provider = None

                for turn in range(LLM_MAX_TURNS):
                    try:
                        response = await asyncio.to_thread(
                            generate_response,
                            history,
                            mcp_tools,
                            active_provider,
                        )

                        if active_provider is None:
                            active_provider = response.provider
                            print(
                                "Conversation provider locked to: "
                                f"{active_provider}"
                            )

                    except Exception as error:
                        print(
                            "\nLLM error:",
                            type(error).__name__,
                            str(error),
                        )
                        break

                    print(f"\n[{response.provider}]")

                    if response.tool_calls:
                        history.append({
                            "role": "assistant_tool_calls",
                            "content": response.text,
                            "tool_calls": response.tool_calls,
                            "provider_content": response.provider_content,
                        })

                    elif response.text:
                        print(response.text)
                        history.append({
                            "role": "assistant",
                            "content": response.text,
                        })

                    if not response.tool_calls:
                        break

                    for call in response.tool_calls:
                        name = call["name"]
                        arguments = call["arguments"]
                        call_id = call["call_id"]

                        if name not in available_tools:
                            result_text = (
                                f"Rejected: '{name}' is not an "
                                "available MCP tool."
                            )

                        elif not validate_tool_arguments(
                            available_tools[name],
                            arguments,
                        ):
                            result_text = (
                                "Rejected: arguments do not match "
                                "the tool schema. Do not retry with "
                                "invented arguments."
                            )

                        elif not approve_tool_call(name, arguments):
                            result_text = (
                                f"Execution of {name} was declined "
                                "by the operator."
                            )

                        else:
                            try:
                                result = await session.call_tool(
                                    name,
                                    arguments=arguments,
                                )
                                result_text = format_tool_result(result)

                                print("\n" + "=" * 60)
                                print(f"MCP TOOL RESULT: {name}")
                                print("=" * 60)
                                print(result_text)
                                print("=" * 60 + "\n")

                            except Exception as error:
                                logger.exception("MCP tool execution failed: %s", name)
                                result_text = (
                                f"Tool execution failed: "
                                f"{type(error).__name__}: {error}"
                                )
                                 
                                print(f"\nMCP EXECUTION ERROR: {result_text}")

                        history.append({
                            "role": "tool_result",
                            "call_id": call_id,
                            "provider_call_id": call.get(
                                "provider_call_id"
                            ),
                            "name": name,
                            "content": result_text,
                        })

                else:
                    print(
                        "\nAgent stopped: maximum reasoning turns reached."
                    )

    print("\nAgent stopped.")


def main():
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as error:
        logger.exception("Agent startup failed: %s", error)


if __name__ == "__main__":
    main()
