"""Security layer: deterministic checks around the agent. Nothing here calls the LLM.

  1. check_question  user input -> "ok" | "too_long" (scope and role-change requests: the agent's OUT_OF_SCOPE)
  2. scan_untrusted  tool output -> instructions aimed at AI agents (flagged, never followed)
  3. neutralise      no text can close or fake the <untrusted_data> wrapper or system tags
  4. READ_ONLY_TOOLS the only data tools the graph may run; a write tool fails at start-up
The agent decides what is in scope; code turns its OUT_OF_SCOPE marker into a fixed refusal.
"""
import json
import re

MAX_QUESTION_CHARS = 2000
MAX_ARG_CHARS = 500

REFUSAL = ("I can only help assess open-source components: their licence, security, maintenance, "
           "privacy (telemetry) and AI-agent skills, or general questions about open-source licences "
           "and dependency risk. Please ask about a specific library, tool, repo or package.")
TOO_LONG = f"The question is too long (max {MAX_QUESTION_CHARS} characters). Please shorten it."
OUT_OF_SCOPE_MARKER = "OUT_OF_SCOPE"
# No answers from memory: a question that names no specific component gets this pointer instead.
GENERAL_REPLY = ("That's a general question, so I won't answer it from memory. "
                 "I can only help assess a specific open-source component (a library, tool, repository or AI-agent "
                 "skill): its licence, security, maintenance and privacy, with evidence for every finding. "
                 "For example: \"Can we use <package> in our product?\"")
BLOCKED = {"too_long": TOO_LONG}  # answered by code, no LLM call

# Tools that only READ. Adding a tool that writes/executes requires changing this set on purpose.
READ_ONLY_TOOLS = frozenset({"get_repo_info", "search_code", "read_file", "check_vulnerabilities", "lookup_register",
                             "scan_skill", "find_version"})

INJECTION_PATTERNS = [  # phrases in TOOL OUTPUT that try to instruct an AI agent
    r"ignore (all |any |the )?(previous|prior|above|earlier|your) (instructions|rules|prompts?)",
    r"disregard (all |any |the )?(previous|prior|above|your) (instructions|rules)",
    r"forget (all |your )?(previous |prior )?(instructions|rules)",
    r"(reveal|print|show|repeat|output) (me )?(your|the) (system )?(prompt|instructions)",
    r"\byou are now\b", r"\bdeveloper mode\b", r"\bjailbreak\b", r"\bDAN mode\b",
    r"</?\s*(system|untrusted_data|assistant)\s*>", r"\bnew instructions\s*:",
    r"\b(note|message|instructions?) (to|for) (the )?(ai|llm|assistant|agent|claude|gpt|model)s?\b",
    r"\bdo not (tell|inform|show) the user\b",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

def check_question(text: str) -> str:
    """'ok' | 'too_long'. Deterministic: no LLM call."""
    return "too_long" if len(text) > MAX_QUESTION_CHARS else "ok"


def scan_untrusted(result: dict) -> list:
    """Instruction-like text inside tool output: [{"snippet", "url"}]. Flagged for the report, never obeyed."""
    hits = []

    def walk(value, url=None):
        if isinstance(value, dict):
            url = value.get("url", url)
            for v in value.values():
                walk(v, url)
        elif isinstance(value, list):
            for v in value:
                walk(v, url)
        elif isinstance(value, str):
            for m in INJECTION_RE.finditer(value):
                start = max(0, m.start() - 40)
                hits.append({"snippet": " ".join(value[start:m.end() + 40].split()), "url": url})

    walk(result)
    return hits[:5]


def neutralise(text: str) -> str:
    """Tool output may not close or open our wrapper (or fake system tags) to escape into instructions."""
    return re.sub(r"<(/?)\s*(untrusted_data|system|assistant)\b", r"[\1\2", text, flags=re.IGNORECASE)


def check_args(args: dict) -> str | None:
    """Size limits on tool arguments (a long argument is a sign of misuse, never needed)."""
    for k, v in args.items():
        if isinstance(v, str) and len(v) > MAX_ARG_CHARS:
            return f"argument '{k}' is too long (max {MAX_ARG_CHARS} characters)"
        if isinstance(v, list) and len(json.dumps(v)) > MAX_ARG_CHARS:
            return f"argument '{k}' is too long"
    return None
