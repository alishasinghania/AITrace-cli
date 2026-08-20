"""Unit tests for pattern_analyzer.py — one positive + one negative case per pattern."""
from __future__ import annotations

import ast
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.pattern_analyzer import (
    PatternFinding,
    PatternAnalysisResult,
    analyze_patterns,
    _build_import_map,
    _deduplicate,
    detect_pat001,
    detect_pat002,
    detect_pat003,
    detect_pat004,
    detect_pat005,
    detect_pat006,
    detect_pat007,
    detect_pat008,
    detect_pat009,
    detect_pat010,
    detect_pat011,
    detect_pat013,
    detect_pat014,
    detect_pat015,
    detect_pat016,
    detect_pat017,
    detect_pat018,
    detect_pat025,
    detect_pat026,
    detect_pat027,
)


def _parse(src: str):
    return ast.parse(src)


def _imap(src: str):
    return _build_import_map(ast.parse(src))


# ---------------------------------------------------------------------------
# PAT-001
# ---------------------------------------------------------------------------

def test_pat001_fires_on_rag_plus_llm():
    src = """
from langchain.vectorstores import Chroma
from anthropic import Anthropic

def chat(query):
    docs = vectorstore.similarity_search(query)
    result = client.messages.create(model="claude", messages=[])
    return result
"""
    findings = detect_pat001(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-001" for f in findings)


def test_pat001_does_not_fire_without_llm_call():
    src = """
def search(query):
    docs = vectorstore.similarity_search(query)
    return docs
"""
    findings = detect_pat001(_parse(src), "app.py", src, _imap(src))
    assert not findings


def test_pat001_high_confidence_with_shared_param():
    src = """
def ask(user_query):
    docs = vectorstore.similarity_search(user_query)
    resp = llm.invoke(user_query)
    return resp
"""
    findings = detect_pat001(_parse(src), "app.py", src, _imap(src))
    assert findings
    assert findings[0].confidence == "high"


# ---------------------------------------------------------------------------
# PAT-002
# ---------------------------------------------------------------------------

def test_pat002_fires_on_python_repl_import():
    src = """
from langchain_experimental.tools import PythonREPLTool
from langchain.agents import AgentExecutor

def run_agent():
    tool = PythonREPLTool()
    executor = AgentExecutor(tools=[tool], agent=agent)
    return executor.invoke({"input": "hello"})
"""
    findings = detect_pat002(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-002" for f in findings)
    assert findings[0].severity == "critical"


def test_pat002_does_not_fire_without_dangerous_tool():
    src = """
from langchain.tools import WikipediaQueryRun
def run():
    tool = WikipediaQueryRun()
"""
    findings = detect_pat002(_parse(src), "app.py", src, _imap(src))
    assert not findings


def test_pat002_fires_on_load_tools_python_repl():
    src = """
from langchain.agents import load_tools, initialize_agent
tools = load_tools(["python_repl"])
"""
    findings = detect_pat002(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-002" for f in findings)


# ---------------------------------------------------------------------------
# PAT-003
# ---------------------------------------------------------------------------

def test_pat003_fires_on_llm_output_to_execute():
    src = """
def run_query():
    response = llm.invoke("generate SQL")
    sql = response.content
    cursor.execute(sql)
"""
    findings = detect_pat003(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-003" for f in findings)


def test_pat003_does_not_fire_on_parameterized_query():
    src = """
def run_query(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    findings = detect_pat003(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-004
# ---------------------------------------------------------------------------

def test_pat004_fires_on_exec_llm_output():
    src = """
def run_code():
    code = llm.invoke("write me code")
    exec(code)
"""
    findings = detect_pat004(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-004" for f in findings)
    assert findings[0].severity == "critical"


def test_pat004_does_not_fire_without_exec():
    src = """
def display_code():
    code = llm.invoke("write code")
    print(code)
"""
    findings = detect_pat004(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-005
# ---------------------------------------------------------------------------

def test_pat005_fires_on_agent_output_in_system():
    src = """
def orchestrate():
    result = crew.kickoff()
    response = client.messages.create(
        system=result,
        messages=[]
    )
"""
    findings = detect_pat005(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-005" for f in findings)


def test_pat005_does_not_fire_without_system_context():
    src = """
def run():
    result = crew.kickoff()
    print(result)
"""
    findings = detect_pat005(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-006
# ---------------------------------------------------------------------------

def test_pat006_fires_on_unbounded_buffer_memory():
    src = """
from langchain.memory import ConversationBufferMemory
memory = ConversationBufferMemory()
"""
    findings = detect_pat006(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-006" for f in findings)


def test_pat006_does_not_fire_on_windowed_memory():
    src = """
from langchain.memory import ConversationBufferWindowMemory
memory = ConversationBufferWindowMemory(k=5)
"""
    findings = detect_pat006(_parse(src), "app.py", src, _imap(src))
    assert not findings


def test_pat006_does_not_fire_on_summary_memory():
    src = """
from langchain.memory import ConversationSummaryMemory
memory = ConversationSummaryMemory(llm=llm)
"""
    findings = detect_pat006(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-007
# ---------------------------------------------------------------------------

def test_pat007_fires_on_tool_with_email():
    src = """
from langchain.tools import tool

@tool
def send_report(message: str):
    smtp = smtplib.SMTP("smtp.example.com")
    smtp.send(message)
"""
    findings = detect_pat007(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-007" for f in findings)


def test_pat007_does_not_fire_on_non_tool_function():
    src = """
def helper():
    smtp = smtplib.SMTP("smtp.example.com")
"""
    findings = detect_pat007(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-008
# ---------------------------------------------------------------------------

def test_pat008_fires_on_db_result_in_prompt():
    src = """
from langchain import PromptTemplate

def chat():
    data = cursor.fetchall()
    template = PromptTemplate.from_template("Answer: {data}")
    prompt = template.format(data=data)
"""
    findings = detect_pat008(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-008" for f in findings)


def test_pat008_does_not_fire_on_static_prompt():
    src = """
def chat():
    prompt = "Tell me about Python"
    result = llm.invoke(prompt)
"""
    findings = detect_pat008(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-009
# ---------------------------------------------------------------------------

def test_pat009_fires_on_pickle_load():
    src = """
import pickle
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
"""
    findings = detect_pat009(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-009" for f in findings)


def test_pat009_fires_on_torch_load_without_weights_only():
    src = """
import torch
model = torch.load('model.pt')
"""
    findings = detect_pat009(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-009" for f in findings)


def test_pat009_does_not_fire_on_torch_load_with_weights_only():
    src = """
import torch
model = torch.load('model.pt', weights_only=True)
"""
    findings = detect_pat009(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-010
# ---------------------------------------------------------------------------

def test_pat010_fires_on_hardcoded_api_key():
    src = """
api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
"""
    findings = detect_pat010(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-010" for f in findings)


def test_pat010_does_not_fire_on_env_var():
    src = """
import os
api_key = os.environ.get("OPENAI_API_KEY")
"""
    findings = detect_pat010(_parse(src), "app.py", src, _imap(src))
    assert not findings


def test_pat010_does_not_fire_on_placeholder():
    src = """
api_key = "your-api-key-here"
"""
    findings = detect_pat010(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-011
# ---------------------------------------------------------------------------

def test_pat011_fires_on_llm_direct_return():
    src = """
from fastapi.responses import JSONResponse

def endpoint():
    result = llm.invoke("hello")
    return JSONResponse(content={"response": result})
"""
    findings = detect_pat011(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-011" for f in findings)


def test_pat011_does_not_fire_with_output_parser():
    src = """
from langchain.output_parsers import PydanticOutputParser

def endpoint():
    result = llm.invoke("hello")
    parser = PydanticOutputParser(pydantic_object=MyModel)
    parsed = parser.parse(result)
    return {"response": parsed}
"""
    findings = detect_pat011(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-013
# ---------------------------------------------------------------------------

def test_pat013_fires_on_multi_agent_chain():
    src = """
def run():
    first_result = agent1.invoke({"input": "research"})
    second_result = agent2.invoke({"input": first_result})
    return second_result
"""
    findings = detect_pat013(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-013" for f in findings)


def test_pat013_does_not_fire_on_single_agent():
    src = """
def run():
    result = agent.invoke({"input": "hello"})
    return result
"""
    findings = detect_pat013(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-014
# ---------------------------------------------------------------------------

def test_pat014_fires_on_write_then_read_memory():
    src = """
def save_and_load():
    vectorstore.add_documents(docs)
    results = vectorstore.similarity_search(query)
"""
    findings = detect_pat014(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-014" for f in findings)


def test_pat014_does_not_fire_on_read_only():
    src = """
def search():
    results = vectorstore.similarity_search(query)
    return results
"""
    findings = detect_pat014(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-015
# ---------------------------------------------------------------------------

def test_pat015_fires_on_dspy_programofthought():
    src = """
import dspy
pot = dspy.ProgramOfThought(signature="question -> answer")
"""
    imap = {"ProgramOfThought": "dspy.ProgramOfThought"}
    findings = detect_pat015(_parse(src), "app.py", src, imap)
    assert any(f.vulnerability_id == "PAT-015" for f in findings)
    assert findings[0].severity == "critical"


def test_pat015_does_not_fire_on_cot():
    src = """
import dspy
cot = dspy.ChainOfThought(signature="question -> answer")
"""
    findings = detect_pat015(_parse(src), "app.py", src, {})
    assert not findings


# ---------------------------------------------------------------------------
# PAT-016
# ---------------------------------------------------------------------------

def test_pat016_fires_on_tool_with_external_fetch():
    src = """
from langchain.tools import tool
import requests

@tool
def fetch_data(url: str):
    resp = requests.get(url)
    return resp.text
"""
    findings = detect_pat016(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-016" for f in findings)


def test_pat016_does_not_fire_on_non_tool_function():
    src = """
import requests

def fetch_data(url: str):
    resp = requests.get(url)
    return resp.text
"""
    findings = detect_pat016(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-017
# ---------------------------------------------------------------------------

def test_pat017_fires_on_direct_stream_yield():
    src = """
def stream_response(query):
    for chunk in llm.stream(query):
        yield chunk
"""
    findings = detect_pat017(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-017" for f in findings)


def test_pat017_does_not_fire_on_buffered_stream():
    src = """
def stream_response(query):
    full_response = ""
    for chunk in llm.stream(query):
        full_response += chunk
    # validate complete
    if validate_output(full_response):
        yield full_response
"""
    findings = detect_pat017(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-018
# ---------------------------------------------------------------------------

def test_pat018_fires_on_db_result_to_llm():
    src = """
def ask():
    data = cursor.fetchall()
    result = llm.invoke(data)
    return result
"""
    findings = detect_pat018(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-018" for f in findings)


def test_pat018_does_not_fire_on_literal_prompt():
    src = """
def ask():
    result = llm.invoke("What is Python?")
    return result
"""
    findings = detect_pat018(_parse(src), "app.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# General / cross-cutting
# ---------------------------------------------------------------------------

def test_async_variants_detected():
    """async def + ainvoke treated same as sync def + invoke."""
    src = """
async def chat(user_query):
    docs = await vectorstore.asimilarity_search(user_query)
    result = await llm.ainvoke(user_query)
    return result
"""
    findings = detect_pat001(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-001" for f in findings)


def test_class_method_variants_detected():
    """self.llm.invoke() should match same as llm.invoke()."""
    src = """
class Agent:
    def run(self, code):
        result = self.llm.invoke("generate")
        exec(result)
"""
    findings = detect_pat004(_parse(src), "app.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-004" for f in findings)


def test_syntax_error_file_skipped_gracefully():
    """analyze_patterns should handle a repo with a broken file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        (repo_root / "bad.py").write_text("def bad(:\n    pass\n")
        (repo_root / "good.py").write_text("x = 1\n")
        result = analyze_patterns(repo_root)
        assert isinstance(result, PatternAnalysisResult)
        # bad.py should appear in scan_errors
        assert any("bad.py" in e for e in result.scan_errors)


def test_empty_repo_returns_empty_result():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = analyze_patterns(Path(tmpdir))
        assert result.files_scanned == 0
        assert result.findings == []


def test_deduplication_keeps_higher_severity():
    f_high = PatternFinding(
        vulnerability_id="PAT-001", title="T", severity="high", confidence="medium",
        category="", owasp_id="", cwe="", file="a.py", line=10, function_name="fn",
        pattern_matched="", evidence=["e1"], framework="",
    )
    f_critical = PatternFinding(
        vulnerability_id="PAT-001", title="T", severity="critical", confidence="medium",
        category="", owasp_id="", cwe="", file="a.py", line=10, function_name="fn",
        pattern_matched="", evidence=["e1", "e2"], framework="",
    )
    result = _deduplicate([f_high, f_critical])
    assert len(result) == 1
    assert result[0].severity == "critical"


def test_import_map_built_correctly():
    src = """
from langchain_experimental.tools import PythonREPLTool
import anthropic
from openai import AsyncOpenAI as OAI
"""
    imap = _build_import_map(_parse(src))
    assert imap.get("PythonREPLTool") == "langchain_experimental.tools.PythonREPLTool"
    assert imap.get("anthropic") == "anthropic"
    assert imap.get("OAI") == "openai.AsyncOpenAI"


def test_pat012_lethal_trifecta_repo_level():
    """PAT-012 fires when all three conditions are present across repo files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        # Condition A: sensitive data access
        (repo_root / "secrets.py").write_text(
            "import os\nkey = os.environ.get('SECRET_KEY')\n"
        )
        # Condition B: external data in agent context
        (repo_root / "rag.py").write_text(
            "docs = vectorstore.similarity_search(query)\n"
        )
        # Condition C: outbound communication
        (repo_root / "notify.py").write_text(
            "import requests\nrequests.post('https://external.example.com', data=payload)\n"
        )
        result = analyze_patterns(repo_root)
        assert any(f.vulnerability_id == "PAT-012" for f in result.findings)


# ---------------------------------------------------------------------------
# PAT-025 user-controlled shell execution
# ---------------------------------------------------------------------------

def test_pat025_fires_on_subprocess_shell_true():
    src = '''
import subprocess

def execute_commands(input_string):
    if "$" in input_string:
        commands = input_string.split("$")[1:]
        for command in commands:
            subprocess.check_output(command, shell=True)
'''
    findings = detect_pat025(_parse(src), "process.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-025" for f in findings)


def test_pat025_does_not_fire_on_argv_list_without_shell():
    src = '''
import subprocess, sys

def boot():
    subprocess.Popen([sys.executable, "server.py"])
'''
    findings = detect_pat025(_parse(src), "main.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-026 user write into RAG corpus
# ---------------------------------------------------------------------------

def test_pat026_fires_on_facts_write_plus_search():
    src = '''
def add_text_to_file(filename, text):
    directory = "training/facts/"
    filepath = directory + filename
    with open(filepath, "a") as file:
        file.write(text + "\\n")

def onMessage(question, history):
    add_text_to_file("training.txt", question)
    docs = store.similarity_search(question)
    return docs
'''
    findings = detect_pat026(_parse(src), "process.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-026" for f in findings)


def test_pat026_does_not_fire_without_retrieval():
    src = '''
def save_note(text):
    directory = "training/facts/"
    with open(directory + "n.txt", "a") as f:
        f.write(text)
'''
    findings = detect_pat026(_parse(src), "notes.py", src, _imap(src))
    assert not findings


# ---------------------------------------------------------------------------
# PAT-027 BaseTool high-risk agency
# ---------------------------------------------------------------------------

def test_pat027_fires_on_send_email_basetool():
    src = '''
from langchain.tools import BaseTool

class SendEmailTool(BaseTool):
    name = "Send Email"
    description = "This tool will send an email to a specified contact."
    def _run(self, tool_input: str) -> str:
        return "Email Sent"
'''
    findings = detect_pat027(_parse(src), "tools.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-027" for f in findings)


def test_pat027_fires_on_http_sink_even_if_name_is_benign():
    src = '''
from langchain.tools import BaseTool
import requests

class LookupTool(BaseTool):
    name = "lookup"
    def _run(self, q: str) -> str:
        return requests.get(q).text
'''
    findings = detect_pat027(_parse(src), "tools.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-027" for f in findings)


def test_pat026_fires_on_add_texts_without_facts_path():
    src = '''
def ingest(user_doc):
    store.add_texts([user_doc])
'''
    findings = detect_pat026(_parse(src), "ingest.py", src, _imap(src))
    assert any(f.vulnerability_id == "PAT-026" for f in findings)

