
import json
import unittest

from google.genai import types

from llm.providers import (
    _history_for_gemini,
    _history_for_groq,
)


class TestGroqHistory(unittest.TestCase):

	def test_tool_call_and_result_ids_match(self):
	    history = [
		{"role": "user", "content": "Discover hosts."},
		{
		    "role": "assistant_tool_calls",
		    "content": "",
		    "tool_calls": [{
		        "call_id": "call-123",
		        "provider_call_id": "call-123",
		        "name": "discover_network",
		        "arguments": {},
		    }],
		},
		{
		    "role": "tool_result",
		    "call_id": "call-123",
		    "provider_call_id": "call-123",
		    "name": "discover_network",
		    "content": '{"host_count": 2}',
		},
	    ]

	    messages = _history_for_groq(history)

	    self.assertEqual(messages[0]["role"], "system")
	    self.assertEqual(messages[1]["role"], "user")

	    assistant_message = messages[2]
	    tool_message = messages[3]

	    self.assertEqual(assistant_message["role"], "assistant")
	    self.assertEqual(
		assistant_message["tool_calls"][0]["id"],
		"call-123",
	    )
	    self.assertEqual(
		assistant_message["tool_calls"][0]["function"]["name"],
		"discover_network",
	    )
	    self.assertEqual(
		json.loads(
		    assistant_message["tool_calls"][0]["function"]["arguments"]
		),
		{},
	    )

	    self.assertEqual(tool_message["role"], "tool")
	    self.assertEqual(tool_message["tool_call_id"], "call-123")
	    self.assertEqual(tool_message["content"], '{"host_count": 2}')


class TestGeminiHistory(unittest.TestCase):

    def test_tool_call_and_result_ids_match(self):
        history = [
            {"role": "user", "content": "Discover hosts."},
            {
                "role": "assistant_tool_calls",
                "content": "",
                "tool_calls": [{
                    "call_id": "call-123",
                    "provider_call_id": "call-123",
                    "name": "discover_network",
                    "arguments": {},
                }],
            },
            {
                "role": "tool_result",
                "call_id": "call-123",
                "provider_call_id": "call-123",
                "name": "discover_network",
                "content": '{"host_count": 2}',
            },
        ]

        contents = _history_for_gemini(history)

        function_call = contents[1].parts[0].function_call
        function_response = contents[2].parts[0].function_response

        self.assertEqual(function_call.id, "call-123")
        self.assertEqual(function_call.name, "discover_network")
        self.assertEqual(function_call.args, {})

        self.assertEqual(function_response.id, "call-123")
        self.assertEqual(function_response.name, "discover_network")
        self.assertEqual(
            function_response.response,
            {"result": '{"host_count": 2}'},
        )

    def test_original_gemini_content_is_preserved(self):
        original_content = types.Content(
            role="model",
            parts=[
                types.Part(
                    function_call=types.FunctionCall(
                        id="gemini-123",
                        name="discover_network",
                        args={},
                    ),
                    thought_signature=b"test-signature",
                )
            ],
        )

        history = [{
            "role": "assistant_tool_calls",
            "content": "",
            "tool_calls": [],
            "provider_content": original_content,
        }]

        contents = _history_for_gemini(history)

        self.assertIs(contents[0], original_content)
        self.assertEqual(
            contents[0].parts[0].thought_signature,
            b"test-signature",
        )

    def test_gemini_tool_response_without_provider_id(self):
        history = [{
            "role": "tool_result",
            "call_id": "internal-123",
            "provider_call_id": None,
            "name": "discover_network",
            "content": "No hosts found.",
        }]

        contents = _history_for_gemini(history)
        response = contents[0].parts[0].function_response

        self.assertIsNone(response.id)
        self.assertEqual(response.name, "discover_network")


if __name__ == "__main__":
    unittest.main()
