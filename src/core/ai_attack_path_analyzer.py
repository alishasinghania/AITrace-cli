"""
AI Attack Path Analyzer for AITrace.

Detects dangerous data flows through the AI architecture graph:
- User Input → Prompt → LLM
- User Input → Retriever → LLM (RAG injection)
- User Input → Agent → Tool → Database
- Embedding → Vector DB (poisoning entry)
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import AttackPathFinding


def _node_ids_by_kind(graph: Dict[str, Any]) -> Dict[str, List[str]]:
    """Index nodes by kind."""
    by_kind: Dict[str, List[str]] = {}
    for n in graph.get("nodes", []):
        kid = n.get("kind", "")
        nid = n.get("id", "")
        if nid:
            by_kind.setdefault(kid, []).append(nid)
    return by_kind


def _outgoing_edges(graph: Dict[str, Any]) -> Dict[str, List[str]]:
    """Map source node id -> list of target node ids."""
    out: Dict[str, List[str]] = {}
    for e in graph.get("edges", []):
        s = e.get("source", "")
        t = e.get("target", "")
        if s and t:
            out.setdefault(s, []).append(t)
    return out


def _node_by_id(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Index nodes by id."""
    idx: Dict[str, Dict[str, Any]] = {}
    for n in graph.get("nodes", []):
        nid = n.get("id", "")
        if nid:
            idx[nid] = n
    return idx


def _find_paths(
    graph: Dict[str, Any],
    start_kinds: List[str],
    end_kinds: List[str],
    max_depth: int = 6,
) -> List[List[str]]:
    """Find simple paths from any start_kind node to any end_kind node."""
    by_kind = _node_ids_by_kind(graph)
    outgoing = _outgoing_edges(graph)
    node_idx = _node_by_id(graph)

    start_ids: List[str] = []
    for k in start_kinds:
        start_ids.extend(by_kind.get(k, []))

    end_ids = set()
    for k in end_kinds:
        end_ids.update(by_kind.get(k, []))

    paths: List[List[str]] = []

    def dfs(node_id: str, path: List[str], visited: set) -> None:
        if len(path) > max_depth:
            return
        if node_id in end_ids and len(path) >= 2:
            paths.append(path[:])
        for t in outgoing.get(node_id, []):
            if t not in visited:
                visited.add(t)
                path.append(t)
                dfs(t, path, visited)
                path.pop()
                visited.discard(t)

    for s in start_ids:
        dfs(s, [s], {s})

    return paths


def analyze_attack_paths(graph: Dict[str, Any]) -> List[AttackPathFinding]:
    """
    Detect attack paths in the AI architecture graph.

    Returns list of AttackPathFinding with type, severity, path, description.
    """
    findings: List[AttackPathFinding] = []
    by_kind = _node_ids_by_kind(graph)
    outgoing = _outgoing_edges(graph)
    node_idx = _node_by_id(graph)

    def path_labels(path: List[str]) -> List[str]:
        return [node_idx.get(n, {}).get("label", n) for n in path]

    # 1. User Input → Prompt → LLM
    paths_ui_llm = _find_paths(
        graph,
        start_kinds=["user_input"],
        end_kinds=["llm_provider"],
        max_depth=5,
    )
    for p in paths_ui_llm:
        labels = path_labels(p)
        has_prompt = any(
            node_idx.get(n, {}).get("kind") == "prompt_builder"
            for n in p
        )
        desc = (
            "User input flows to LLM prompt (prompt injection risk)"
            if has_prompt
            else "User input flows to LLM (direct injection risk)"
        )
        findings.append(
            AttackPathFinding(
                type="ai_attack_path",
                severity="critical",
                path=labels,
                description=desc,
            )
        )

    # 2. User Input → Retriever → LLM (RAG injection)
    paths_ui_ret_llm = _find_paths(
        graph,
        start_kinds=["user_input"],
        end_kinds=["retriever", "llm_provider"],
        max_depth=5,
    )
    for p in paths_ui_ret_llm:
        kinds = [node_idx.get(n, {}).get("kind") for n in p]
        if "retriever" in kinds and "llm_provider" in kinds:
            labels = path_labels(p)
            findings.append(
                AttackPathFinding(
                    type="ai_attack_path",
                    severity="critical",
                    path=labels,
                    description="User input → retriever → LLM (RAG injection risk)",
                )
            )
            break

    # 3. User Input → Agent → Tool → Database
    paths_ui_agent = _find_paths(
        graph,
        start_kinds=["user_input"],
        end_kinds=["agent", "tool", "database"],
        max_depth=6,
    )
    for p in paths_ui_agent:
        kinds = [node_idx.get(n, {}).get("kind") for n in p]
        if "agent" in kinds and ("tool" in kinds or "database" in kinds):
            labels = path_labels(p)
            findings.append(
                AttackPathFinding(
                    type="ai_attack_path",
                    severity="critical",
                    path=labels,
                    description="User input → agent → tool/database (agent abuse risk)",
                )
            )
            break

    # 4. Embedding → Vector DB (poisoning entry)
    paths_emb_vdb = _find_paths(
        graph,
        start_kinds=["document_loader", "embedding_model"],
        end_kinds=["vector_db"],
        max_depth=4,
    )
    for p in paths_emb_vdb:
        labels = path_labels(p)
        findings.append(
            AttackPathFinding(
                type="ai_attack_path",
                severity="high",
                path=labels,
                description="Document/embedding → vector DB (RAG poisoning entry point)",
            )
        )
        break

    # Dedupe by path tuple
    seen: set = set()
    unique: List[AttackPathFinding] = []
    for f in findings:
        key = (tuple(f.path), f.description)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
