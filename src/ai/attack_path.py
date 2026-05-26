from __future__ import annotations

from typing import Optional


def build_attack_graph(attack_paths: list[dict], target: str) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []

    nodes.append({
        "id": "target",
        "label": target,
        "type": "target",
        "severity": "info",
    })

    for i, path in enumerate(attack_paths):
        entry = path.get("entry_point", "Unknown")
        exploitation = path.get("exploitation", "")
        pivot = path.get("pivot", "")
        impact = path.get("impact", "")
        prob = path.get("probability", "medium")

        entry_id = f"entry_{i}"
        exploit_id = f"exploit_{i}"
        pivot_id = f"pivot_{i}"
        impact_id = f"impact_{i}"

        sev_map = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}

        nodes.append({"id": entry_id, "label": entry[:60], "type": "entry", "severity": sev_map.get(prob, "medium")})
        nodes.append({"id": exploit_id, "label": exploitation[:60], "type": "exploit", "severity": "high"})
        nodes.append({"id": pivot_id, "label": pivot[:60], "type": "pivot", "severity": "medium"})
        nodes.append({"id": impact_id, "label": impact[:60], "type": "impact", "severity": "critical"})

        edges.append({"source": "target", "target": entry_id, "label": "leads to"})
        edges.append({"source": entry_id, "target": exploit_id, "label": "exploit"})
        edges.append({"source": exploit_id, "target": pivot_id, "label": "pivot"})
        edges.append({"source": pivot_id, "target": impact_id, "label": "impact"})

    return {"nodes": nodes, "edges": edges}
