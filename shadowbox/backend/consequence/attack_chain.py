"""
ShadowBox — Attack Chain Builder
Constructs a directed acyclic graph (DAG) from telemetry events
for the Attack Replay visualization.
"""
import os


def build_attack_chain(telemetry: dict, file_path: str) -> dict:
    """
    Build an ordered attack chain DAG from telemetry events.
    Returns {nodes: [...], edges: [...]} structure.
    """
    nodes = []
    edges = []
    node_id_counter = [0]

    def add_node(label: str, node_type: str) -> str:
        node_id_counter[0] += 1
        nid = str(node_id_counter[0])
        nodes.append({"id": nid, "label": label, "type": node_type})
        return nid

    # ── Root node: the uploaded file ─────────────────────────────────────
    filename = os.path.basename(file_path)
    root_id = add_node(filename, "file")
    last_id = root_id

    processes = telemetry.get("processes", [])
    network = telemetry.get("network", [])
    files = telemetry.get("files", [])
    persistence = telemetry.get("persistence", [])

    # ── Process nodes ────────────────────────────────────────────────────
    process_ids = {}
    for proc in processes:
        cmd = proc.get("command", "unknown")
        # Truncate long commands
        label = cmd[:60] + "..." if len(cmd) > 60 else cmd
        nid = add_node(label, "process")
        process_ids[proc.get("pid", 0)] = nid
        edges.append({"from": last_id, "to": nid})
        last_id = nid

    # ── Network nodes ────────────────────────────────────────────────────
    for net in network:
        domain = net.get("domain") or net.get("ip", "unknown")
        port = net.get("port", 0)
        label = f"→ {domain}:{port}" if port else f"→ {domain}"
        nid = add_node(label, "network")
        edges.append({"from": last_id, "to": nid})

    # ── File operation nodes ─────────────────────────────────────────────
    download_node_id = None
    for f in files:
        path = f.get("path", "unknown")
        operation = f.get("operation", "accessed")
        label = f"{operation}: {os.path.basename(path)}"
        node_type = "file_op"

        if operation == "created" and any(kw in path.lower() for kw in ["payload", "tmp", "download"]):
            node_type = "download"
            download_node_id = add_node(label, node_type)
            edges.append({"from": last_id, "to": download_node_id})
        else:
            nid = add_node(label, node_type)
            parent = download_node_id or last_id
            edges.append({"from": parent, "to": nid})

    # ── Persistence nodes ────────────────────────────────────────────────
    for p in persistence:
        p_type = p.get("type", "unknown")
        detail = p.get("detail", "")
        label = f"🔒 {p_type}: {detail[:50]}" if detail else f"🔒 {p_type} persistence"
        nid = add_node(label, "persistence")
        edges.append({"from": last_id, "to": nid})

    # ── Deduplicate edges ────────────────────────────────────────────────
    seen_edges = set()
    unique_edges = []
    for edge in edges:
        key = (edge["from"], edge["to"])
        if key not in seen_edges and edge["from"] != edge["to"]:
            seen_edges.add(key)
            unique_edges.append(edge)

    return {"nodes": nodes, "edges": unique_edges}
