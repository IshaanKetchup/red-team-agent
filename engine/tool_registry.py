def _provider_schema(tool):
    """Return a provider-compatible JSON schema."""
    schema = tool.inputSchema or {}

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}

    result = {
        "type": "object",
        "properties": properties,
    }

    required = schema.get("required", [])
    if required:
        result["required"] = required

    return result


def to_openai_tools(mcp_tools):
    """Convert MCP tools into OpenAI-compatible definitions."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": _provider_schema(tool),
            },
        }
        for tool in mcp_tools
    ]


def to_gemini_declarations(mcp_tools):
    """Convert MCP tools into Gemini function declarations."""
    return [
        {
            "name": tool.name,
            "description": tool.description or "",
            "parameters_json_schema": _provider_schema(tool),
        }
        for tool in mcp_tools
    ]
