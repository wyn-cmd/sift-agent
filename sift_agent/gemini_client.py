import os

# Gemini function-calling client that satisfies the agent's small LLMClient protocol
class GeminiClient:
    def __init__(self, model_name: str, api_key: str | None = None, client=None):
        self.model_name = model_name
        if client is not None:
            self.client = client
            return
        # Lazy import so the test suite does not need google-genai installed
        from google import genai
        key = api_key or os.environ.get('GEMINI_API_KEY')
        if not key:
            raise ValueError('GEMINI_API_KEY environment variable not set')
        self.client = genai.Client(api_key=key)

    # Turn the agent's message list into the system text and Gemini contents. Tool results are
    # sent as user text carrying the tool_call_id, so the model can cite it and never sees
    # tool output in a privileged role.
    @staticmethod
    def convert(messages: list[dict]) -> tuple[str, list[dict]]:
        system = ''
        contents = []
        for m in messages:
            role = m.get('role')
            text = m.get('content', '') or ''
            if role == 'system':
                system = text
            elif role == 'assistant':
                contents.append({'role': 'model', 'parts': [{'text': text}]})
            elif role == 'tool':
                label = f"[tool result: {m.get('name')} tool_call_id={m.get('tool_call_id', 'none')}]\n{text}"
                contents.append({'role': 'user', 'parts': [{'text': label}]})
        if not contents:
            contents.append({'role': 'user', 'parts': [{'text': 'Begin the investigation.'}]})
        # Gemini wants the first turn to be from the user and roles to alternate sensibly
        merged = []
        for c in contents:
            if merged and merged[-1]['role'] == c['role']:
                merged[-1]['parts'].extend(c['parts'])
            else:
                merged.append(c)
        if merged[0]['role'] != 'user':
            merged.insert(0, {'role': 'user', 'parts': [{'text': 'Begin the investigation.'}]})
        if merged[-1]['role'] == 'model':
            merged.append({'role': 'user', 'parts': [{'text': 'Continue: call another tool or give the final cited report.'}]})
        return system, merged

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        from google.genai import types
        system, contents = self.convert(messages)
        config = types.GenerateContentConfig(
            system_instruction=system,
            tools=[types.Tool(function_declarations=tools)],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        response = self.client.models.generate_content(model=self.model_name, contents=contents, config=config)
        text_parts = []
        calls = []
        cands = response.candidates or []
        parts = cands[0].content.parts if cands and cands[0].content and cands[0].content.parts else []
        for p in parts:
            if getattr(p, 'function_call', None):
                fc = p.function_call
                calls.append({'name': fc.name, 'arguments': dict(fc.args or {})})
            elif getattr(p, 'text', None):
                text_parts.append(p.text)
        out = {'content': '\n'.join(text_parts), 'tool_calls': calls}
        return out
