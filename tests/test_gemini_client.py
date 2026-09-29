from sift_agent.gemini_client import GeminiClient
from sift_agent.tools import find_vol

# Tool output must reach Gemini as user text carrying the call id, never in a privileged role
def test_convert_wraps_tool_output_as_user_text():
    msgs = [
        {'role': 'system', 'content': 'sys'},
        {'role': 'assistant', 'content': 'checking'},
        {'role': 'tool', 'name': 'windows.pslist', 'tool_call_id': 'abc', 'content': '[UNTRUSTED TOOL OUTPUT] x'},
    ]
    system, contents = GeminiClient.convert(msgs)
    assert system == 'sys'
    assert contents[0]['role'] == 'user'
    assert contents[-1]['role'] == 'user'
    assert 'tool_call_id=abc' in contents[-1]['parts'][-1]['text']
    assert all(c['role'] in ('user', 'model') for c in contents)

# Roles must alternate: consecutive same-role turns are merged
def test_convert_merges_consecutive_roles():
    msgs = [{'role': 'system', 'content': 's'},
            {'role': 'tool', 'name': 'a', 'tool_call_id': '1', 'content': 'x'},
            {'role': 'tool', 'name': 'b', 'tool_call_id': '2', 'content': 'y'}]
    _, contents = GeminiClient.convert(msgs)
    assert len(contents) == 1 and len(contents[0]['parts']) == 2

# A history that ends on a model turn gets a user nudge so the API accepts it
def test_convert_never_ends_on_model_turn():
    _, contents = GeminiClient.convert([{'role': 'system', 'content': 's'}, {'role': 'assistant', 'content': 'hi'}])
    assert contents[0]['role'] == 'user' and contents[-1]['role'] == 'user'

# Function calls and text in a response are split into the agent's dict shape
def test_chat_parses_function_calls():
    class FC:
        name = 'windows.pslist'
        args = {'a': 1}
    class Part:
        def __init__(self, text=None, fc=None):
            self.text = text
            self.function_call = fc
    class Content:
        parts = [Part(text='hello'), Part(fc=FC())]
    class Cand:
        content = Content()
    class Resp:
        candidates = [Cand()]
    class Models:
        def generate_content(self, **kw):
            return Resp()
    class Client:
        models = Models()
    out = GeminiClient('m', client=Client()).chat([{'role': 'system', 'content': 's'}], [])
    assert out['content'] == 'hello'
    assert out['tool_calls'] == [{'name': 'windows.pslist', 'arguments': {'a': 1}}]

# find_vol always returns a non-empty command string
def test_find_vol_returns_string():
    assert isinstance(find_vol(), str) and find_vol()
