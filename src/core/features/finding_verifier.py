"""
Static finding verifier — enriches exploit payloads with additional static evidence.

For each ExploitPayload, runs extra AST/grep checks on the target file to decide
whether the finding is CONFIRMED, LIKELY, or UNCERTAIN without any runtime calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from core.features.exploit_synthesizer import ExploitPayload

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

VERDICT_CONFIRMED  = "confirmed"
VERDICT_LIKELY     = "likely"
VERDICT_UNCERTAIN  = "uncertain"

_EXTERNAL_PROVIDERS = ("openai", "anthropic", "cohere", "google", "mistral", "huggingface")

# Patterns that suggest sanitization is happening near the LLM call
_SANITIZE_HINTS = (
    "sanitize", "validate", "escape", "strip_tags", "bleach",
    "html.escape", "re.sub", "filter", "clean", "purify",
)

# Patterns that confirm user input is interpolated directly into the prompt
_INTERPOLATION_HINTS = ('f"', "f'", ".format(", " + ", "join(", "%s", "% (", "template")

# Variable names that are clearly secrets
_SECRET_KEYWORDS = (
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "credential", "auth", "private_key", "access_key", "client_secret",
)


@dataclass
class VerificationResult:
    """Static verification outcome for a single ExploitPayload."""

    finding_id: str
    verdict: str          # CONFIRMED / LIKELY / UNCERTAIN
    confidence: int       # 0–100
    evidence_for: List[str] = field(default_factory=list)
    evidence_against: List[str] = field(default_factory=list)
    recommendation: str = ""

    @property
    def is_confirmed(self) -> bool:
        return self.verdict == VERDICT_CONFIRMED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
            "recommendation": self.recommendation,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_window(file_path: Path, center_line: Optional[int], radius: int = 12) -> str:
    """Return up to 2*radius lines of source centred on center_line."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if center_line:
            start = max(0, center_line - radius - 1)
            end = min(len(lines), center_line + radius)
        else:
            start, end = 0, min(len(lines), radius * 2)
        return "\n".join(lines[start:end]).lower()
    except OSError:
        return ""


def _sink_is_external(sink: str) -> bool:
    sl = sink.lower()
    return any(p in sl for p in _EXTERNAL_PROVIDERS)


def _recommendation(verdict: str, payload: "ExploitPayload") -> str:
    if verdict == VERDICT_CONFIRMED:
        return (
            f"High confidence — apply the payload at {payload.target_file}"
            + (f":{payload.target_line}" if payload.target_line else "")
            + " to demonstrate exploitability. Remediate by sanitizing "
            f"'{payload.source_type}' before passing to '{payload.sink_type}'."
        )
    if verdict == VERDICT_LIKELY:
        return (
            "Probable finding — manual code review recommended to confirm "
            "no out-of-band sanitization is present before accepting as exploitable."
        )
    return (
        "Insufficient static evidence — the flow exists but exploitability "
        "could not be confirmed without additional context or runtime testing."
    )


# ---------------------------------------------------------------------------
# Per-source verifiers
# ---------------------------------------------------------------------------

def _verify_user_input(payload: "ExploitPayload", repo_root: Path) -> VerificationResult:
    score = 40
    ev_for: List[str] = []
    ev_against: List[str] = []

    # Unsanitized flag from taint tracker (already computed)
    ev_for.append("Taint analysis: no sanitization on the source→sink path")
    score += 20

    # External provider — data leaves org boundary
    if _sink_is_external(payload.sink_type):
        ev_for.append(f"Sink '{payload.sink_type}' is an external AI provider — data leaves network")
        score += 15

    # Read source lines and look for direct interpolation
    if payload.target_file and payload.target_file != "<vector_store>":
        window = _read_window(repo_root / payload.target_file, payload.target_line)
        if window:
            hits = [h for h in _INTERPOLATION_HINTS if h in window]
            if hits:
                ev_for.append(
                    f"Direct string interpolation detected near sink ({', '.join(hits[:3])})"
                )
                score += 15
            else:
                ev_against.append("No obvious string interpolation found near sink — may use a builder")
                score -= 5

            sanitize_hits = [h for h in _SANITIZE_HINTS if h in window]
            if sanitize_hits:
                ev_against.append(
                    f"Potential sanitization call near sink ({', '.join(sanitize_hits[:2])})"
                )
                score -= 20
            else:
                ev_for.append("No sanitization calls detected near the LLM sink")
                score += 5

    score = max(0, min(100, score))
    verdict = VERDICT_CONFIRMED if score >= 75 else (VERDICT_LIKELY if score >= 50 else VERDICT_UNCERTAIN)
    return VerificationResult(
        finding_id=payload.finding_id,
        verdict=verdict,
        confidence=score,
        evidence_for=ev_for,
        evidence_against=ev_against,
        recommendation=_recommendation(verdict, payload),
    )


def _verify_env_exposure(payload: "ExploitPayload", repo_root: Path) -> VerificationResult:
    score = 35
    ev_for: List[str] = []
    ev_against: List[str] = []

    # Variable name is a known secret keyword
    var = payload.sink_type.lower()  # sink_type holds variable name for SE payloads
    var_name = payload.title.split("'")[1].lower() if "'" in payload.title else ""
    if any(kw in var_name for kw in _SECRET_KEYWORDS):
        ev_for.append(f"Variable name '{var_name}' matches known secret keyword pattern")
        score += 20

    # External provider
    if _sink_is_external(payload.sink_type):
        ev_for.append(f"Secret reaches external provider '{payload.sink_type}' — critical data boundary crossing")
        score += 25
    else:
        ev_for.append("Secret reaches internal LLM sink — exploitable within trust boundary")
        score += 10

    # Check if variable appears in prompt construction near the sink
    if payload.target_file:
        window = _read_window(repo_root / payload.target_file, payload.target_line)
        if var_name and var_name in window:
            ev_for.append(f"Variable '{var_name}' confirmed present in code near LLM call")
            score += 15

        # Look for masking patterns
        if any(h in window for h in ("mask", "redact", "***", "[:4]", "[-4:]", "xxxx")):
            ev_against.append("Possible masking/redaction of secret value detected near sink")
            score -= 20

        if any(h in window for h in _INTERPOLATION_HINTS):
            ev_for.append("Direct interpolation of variable into prompt string detected")
            score += 10

    score = max(0, min(100, score))
    verdict = VERDICT_CONFIRMED if score >= 75 else (VERDICT_LIKELY if score >= 50 else VERDICT_UNCERTAIN)
    return VerificationResult(
        finding_id=payload.finding_id,
        verdict=verdict,
        confidence=score,
        evidence_for=ev_for,
        evidence_against=ev_against,
        recommendation=_recommendation(verdict, payload),
    )


def _verify_rag(payload: "ExploitPayload", repo_root: Path) -> VerificationResult:
    score = 50
    ev_for: List[str] = []
    ev_against: List[str] = []

    ev_for.append("RAG pipeline detected — retrieval results are passed to LLM context")
    score += 10

    # Look for any retrieval result filtering
    py_files = list(repo_root.rglob("*.py"))[:30]
    rag_keywords = ("similarity_search", "query", "retrieve", "vectorstore", "chroma", "pinecone", "weaviate")
    filter_keywords = ("filter", "validate", "sanitize", "score_threshold", "max_marginal")

    rag_found = False
    filter_found = False
    for f in py_files:
        try:
            src = f.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if any(k in src for k in rag_keywords):
            rag_found = True
        if rag_found and any(k in src for k in filter_keywords):
            filter_found = True
            break

    if rag_found:
        ev_for.append("RAG retrieval call confirmed in source code")
        score += 15
    if filter_found:
        ev_against.append("Score threshold or filter detected in retrieval — may limit injection surface")
        score -= 15
    else:
        ev_for.append("No score threshold or document filtering detected on retrieval results")
        score += 10

    score = max(0, min(100, score))
    verdict = VERDICT_CONFIRMED if score >= 75 else (VERDICT_LIKELY if score >= 50 else VERDICT_UNCERTAIN)
    return VerificationResult(
        finding_id=payload.finding_id,
        verdict=verdict,
        confidence=score,
        evidence_for=ev_for,
        evidence_against=ev_against,
        recommendation=_recommendation(verdict, payload),
    )


def _verify_agent(payload: "ExploitPayload", repo_root: Path) -> VerificationResult:
    score = 45
    ev_for: List[str] = []
    ev_against: List[str] = []

    ev_for.append("Agent framework with tool-calling detected — tool responses reach LLM reasoning loop")
    score += 15

    if payload.target_file and payload.target_file != "<vector_store>":
        window = _read_window(repo_root / payload.target_file, payload.target_line)
        if "tool" in window or "function_call" in window or "tool_call" in window:
            ev_for.append("Tool invocation pattern confirmed near flagged code")
            score += 15
        if any(h in window for h in ("validate", "trust", "verify", "safe")):
            ev_against.append("Possible trust/validation check on tool response")
            score -= 15

    if _sink_is_external(payload.sink_type):
        ev_for.append("Agent sends tool results to external LLM provider")
        score += 10

    score = max(0, min(100, score))
    verdict = VERDICT_CONFIRMED if score >= 75 else (VERDICT_LIKELY if score >= 50 else VERDICT_UNCERTAIN)
    return VerificationResult(
        finding_id=payload.finding_id,
        verdict=verdict,
        confidence=score,
        evidence_for=ev_for,
        evidence_against=ev_against,
        recommendation=_recommendation(verdict, payload),
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

_VERIFIER_MAP = {
    "user_input":    _verify_user_input,
    "environment":   _verify_env_exposure,
    "rag_document":  _verify_rag,
    "tool_response": _verify_agent,
}


def verify_statically(
    payloads: List["ExploitPayload"],
    repo_root: Path,
) -> List[VerificationResult]:
    """Run static verification for each payload. Returns one result per payload."""
    results: List[VerificationResult] = []
    for payload in payloads:
        verifier = _VERIFIER_MAP.get(payload.source_type)
        if verifier:
            results.append(verifier(payload, repo_root))
        else:
            # Generic fallback — mark uncertain
            results.append(VerificationResult(
                finding_id=payload.finding_id,
                verdict=VERDICT_UNCERTAIN,
                confidence=30,
                evidence_for=["Flow detected by taint analysis"],
                evidence_against=["No source-specific verifier available for this flow type"],
                recommendation=_recommendation(VERDICT_UNCERTAIN, payload),
            ))
    return results


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

_VERDICT_SYMBOL = {
    VERDICT_CONFIRMED: "✔ CONFIRMED",
    VERDICT_LIKELY:    "~ LIKELY",
    VERDICT_UNCERTAIN: "? UNCERTAIN",
}

_VERDICT_COLOR_MD = {
    VERDICT_CONFIRMED: "🔴",
    VERDICT_LIKELY:    "🟠",
    VERDICT_UNCERTAIN: "🟡",
}


def print_verification(payloads: List["ExploitPayload"], results: List[VerificationResult]) -> None:
    payload_map = {p.finding_id: p for p in payloads}
    sep = "-" * 72

    for r in results:
        p = payload_map.get(r.finding_id)
        title = p.title if p else r.finding_id
        symbol = _VERDICT_SYMBOL[r.verdict]
        print(f"  {symbol}  [{r.confidence}% confidence]  {title}")
        for ev in r.evidence_for:
            print(f"    + {ev}")
        for ev in r.evidence_against:
            print(f"    - {ev}")
        print(f"    → {r.recommendation}")
        print()


def verification_to_markdown(
    payloads: List["ExploitPayload"],
    results: List[VerificationResult],
) -> str:
    if not results:
        return ""

    payload_map = {p.finding_id: p for p in payloads}
    lines = [
        "",
        "## Static Verification Results",
        "",
        "| ID | Finding | Verdict | Confidence |",
        "|---|---|---|---|",
    ]
    for r in results:
        p = payload_map.get(r.finding_id)
        title = p.title if p else r.finding_id
        icon = _VERDICT_COLOR_MD[r.verdict]
        lines.append(f"| `{r.finding_id}` | {title} | {icon} {r.verdict.upper()} | {r.confidence}% |")

    lines += ["", "### Evidence detail", ""]
    for r in results:
        p = payload_map.get(r.finding_id)
        title = p.title if p else r.finding_id
        icon = _VERDICT_COLOR_MD[r.verdict]
        lines += [
            f"**{icon} {r.finding_id} — {title}**",
            "",
        ]
        for ev in r.evidence_for:
            lines.append(f"- ✅ {ev}")
        for ev in r.evidence_against:
            lines.append(f"- ❌ {ev}")
        lines += [f"- 💡 {r.recommendation}", ""]

    return "\n".join(lines)
