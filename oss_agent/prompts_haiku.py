"""System prompt for smaller models (Haiku). Built from prompts.SYSTEM_PROMPT, which stays unchanged.

Why: in live runs Haiku gathered more than the question needed (a telemetry search on a version question, a
README read after the facts were in). The edits below are general principles about WHEN TO STOP, nothing
case-specific. Used when LLM_MODEL contains "haiku" (graph.build_graph).
"""
from oss_agent.prompts import SYSTEM_PROMPT as BASE

# The base prompt's "if unsure, check privacy anyway" invites an extra search on every question.
OLD_PRIVACY = """   If you are unsure, treat it as required and check lightly: one code search for what it collects or sends, and
   read what that finds."""
NEW_PRIVACY = """   Otherwise privacy is not required: do not search for telemetry or data collection, and leave privacy
   not_checked."""

OLD_GATHER = "   updates in one or two sentences. Stop when more calls would not change the answer."
NEW_GATHER = """   updates in one or two sentences. Stop when more calls would not change the answer.
   Before each call, name the area it serves and the result that would change the verdict. If you cannot name
   both, do not make the call.
   - Check only the areas the question needs (see step 2). Do not add checks for areas the user did not ask
     about and the stated use does not involve.
   - Once a finding already decides the verdict as red (a malicious release, an end-of-life version, an
     archived repository), submit the report: more checks cannot make it better.
   - Do not repeat a fact another tool already returned (for example by reading a README or searching code
     for it).
   - Versions the user gave are exact: check them directly, without looking them up first."""

for old, new in ((OLD_PRIVACY, NEW_PRIVACY), (OLD_GATHER, NEW_GATHER)):
    assert BASE.count(old) == 1, f"base prompt changed, update prompts_haiku.py: {old[:50]!r}"
SYSTEM_PROMPT = BASE.replace(OLD_PRIVACY, NEW_PRIVACY).replace(OLD_GATHER, NEW_GATHER)
