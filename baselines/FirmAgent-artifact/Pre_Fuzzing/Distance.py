import argparse
import csv
import json
import os
import re
from typing import Dict, List, Tuple

import networkx as nx


def _node_addr(node):
    return getattr(node, "addr", node)


def calculate_weight(total_edges_in_cfg, total_indirect_edges):
    if total_indirect_edges:
        weight = round(total_edges_in_cfg / total_indirect_edges, 3)
    else:
        weight = 1
    return min(weight, 10)


def compute_shortest_distance(rfg, node, exit_node):
    try:
        return nx.shortest_path_length(rfg, source=node, target=exit_node, weight='weight')
    except nx.NetworkXNoPath:
        return None


def precompute_shortest_paths(rfg_reverse, pr_exit_nodes):
    shortest_paths_cache = {}
    for exit_node in pr_exit_nodes:
        if exit_node not in rfg_reverse:
            print(f"Exit node {_node_addr(exit_node)} not found in graph")
            continue
        shortest_paths_cache[exit_node] = nx.single_source_dijkstra_path_length(
            rfg_reverse,
            exit_node,
            weight='weight',
        )
    return shortest_paths_cache


def compute_node_depth_for_region(node, exit_node, shortest_paths_cache):
    if exit_node not in shortest_paths_cache:
        return -1
    return shortest_paths_cache[exit_node].get(node, -1)


def process_pr_region_depth(pr_region, pr_exit_nodes, region_reach, rfg_graph):
    rfg_reverse = rfg_graph.reverse(copy=True)
    shortest_paths_cache = precompute_shortest_paths(rfg_reverse, pr_exit_nodes)

    nearest_sink_distance = {}
    max_distance_in_region = -1

    for node in pr_region:
        node_addr = _node_addr(node)
        best_sink_addr = None
        best_distance = None

        for exit_node in pr_exit_nodes:
            exit_addr = _node_addr(exit_node)
            if exit_addr not in region_reach:
                continue

            node_distance = compute_node_depth_for_region(node, exit_node, shortest_paths_cache)
            if node_distance < 0:
                continue

            if best_distance is None or node_distance < best_distance:
                best_distance = node_distance
                best_sink_addr = exit_addr

        if best_distance is None:
            continue

        nearest_sink_distance[node_addr] = (best_sink_addr, best_distance)
        if best_distance > max_distance_in_region:
            max_distance_in_region = best_distance

    if max_distance_in_region < 0:
        return {}

    node_depth_map = {}
    for node_addr, (sink_addr, sink_distance) in nearest_sink_distance.items():
        depth_score = max_distance_in_region - sink_distance
        node_depth_map[node_addr] = (sink_addr, depth_score)

    return node_depth_map


def calculate_node_reachability(PR_node_depth_all, region_reach, w):
    node_score = {}
    for node_addr, (sink_addr, node_depth) in PR_node_depth_all.items():
        sink_dis = region_reach.get(sink_addr, 0)
        node_score[node_addr] = node_depth + w * sink_dis
    return node_score


def calculate_PR_node_reachability(PR_regions, pr_region_exits, region_reach, rfg_graph, indirect_edges):
    total_edges_in_cfg = rfg_graph.number_of_edges()
    total_indirect_edges = len(indirect_edges)
    w = calculate_weight(total_edges_in_cfg, total_indirect_edges)

    PR_node_depth_all = {}
    for pr_region_id, pr_region in PR_regions:
        pr_exit_nodes = pr_region_exits.get(pr_region_id, [])
        if not pr_exit_nodes:
            continue

        one_region_depth = process_pr_region_depth(pr_region, pr_exit_nodes, region_reach, rfg_graph)
        PR_node_depth_all.update(one_region_depth)

    PR_node_reachability_all = calculate_node_reachability(PR_node_depth_all, region_reach, w)
    return PR_node_reachability_all, w, PR_node_depth_all


def _parse_sink_scope_ranges(path: str) -> List[Tuple[int, int]]:
    if not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        raw = file.read()

    ranges: List[Tuple[int, int]] = []
    for start_hex, end_hex in re.findall(r"(0x[0-9a-fA-F]+)\.\.(0x[0-9a-fA-F]+)", raw):
        start = int(start_hex, 16)
        end = int(end_hex, 16)
        if end < start:
            start, end = end, start
        ranges.append((start, end))

    dedup = list(dict.fromkeys(ranges))
    return dedup


def _build_pseudo_cfg_from_ranges(
    addr_ranges: List[Tuple[int, int]],
    block_step: int,
) -> Tuple[List[Tuple[int, List[int]]], Dict[int, List[int]], nx.DiGraph]:
    graph = nx.DiGraph()
    pr_regions: List[Tuple[int, List[int]]] = []
    pr_region_exits: Dict[int, List[int]] = {}

    for index, (start_addr, end_addr) in enumerate(addr_ranges):
        region_id = index + 1
        nodes = list(range(start_addr, end_addr + 1, block_step))
        if not nodes:
            nodes = [start_addr]

        if nodes[-1] != end_addr:
            nodes.append(end_addr)

        for node in nodes:
            graph.add_node(node)

        for pos in range(len(nodes) - 1):
            src = nodes[pos]
            dst = nodes[pos + 1]
            if src != dst:
                graph.add_edge(src, dst, weight=1.0)

        pr_regions.append((region_id, nodes))
        pr_region_exits[region_id] = [end_addr]

    return pr_regions, pr_region_exits, graph


def _compute_scores_by_paper(
    pr_regions: List[Tuple[int, List[int]]],
    pr_region_exits: Dict[int, List[int]],
    graph: nx.DiGraph,
    indirect_edges_count: int,
) -> Tuple[List[Dict[str, float]], float]:
    total_edges = graph.number_of_edges()
    w = calculate_weight(total_edges, indirect_edges_count)

    reverse_graph = graph.reverse(copy=True)
    all_exit_nodes = sorted({sink for sinks in pr_region_exits.values() for sink in sinks})
    shortest_to_sink_cache = precompute_shortest_paths(reverse_graph, all_exit_nodes)

    rows: List[Dict[str, float]] = []
    for region_id, region_nodes in pr_regions:
        if not region_nodes:
            continue

        region_exits = pr_region_exits.get(region_id, [])
        if not region_exits:
            continue

        region_entry = region_nodes[0]
        depth_map = nx.single_source_dijkstra_path_length(graph, region_entry, weight="weight")

        for node in region_nodes:
            nearest_sink = None
            nearest_distance = None

            for sink in region_exits:
                sink_dist_map = shortest_to_sink_cache.get(sink, {})
                sink_distance = sink_dist_map.get(node)
                if sink_distance is None:
                    continue
                if nearest_distance is None or sink_distance < nearest_distance:
                    nearest_distance = sink_distance
                    nearest_sink = sink

            if nearest_sink is None or nearest_distance is None:
                continue

            depth = float(depth_map.get(node, 0.0))
            score = depth + w * float(nearest_distance)
            rows.append(
                {
                    "region_id": region_id,
                    "node": node,
                    "nearest_sink": nearest_sink,
                    "depth": depth,
                    "distance_to_sink": float(nearest_distance),
                    "w": w,
                    "score": score,
                }
            )

    rows.sort(key=lambda item: item["score"], reverse=True)
    return rows, w


def _load_cfg(path: str):
    """Load sink_cfg.json (schema v1) into (nodes, edges, roots, sinks).

    Returns a dict with keyed structures or None if the file cannot be read.
    """
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as file:
        cfg = json.load(file)

    if not isinstance(cfg, dict) or "nodes" not in cfg:
        return None

    node_by_addr = {int(n["address"]): n for n in cfg["nodes"]}
    edges = []
    for edge in cfg["edges"]:
        edges.append((int(edge["source"]), int(edge["target"]), edge.get("kind", "cfg")))
    roots = [int(r) for r in cfg.get("roots", [])]
    sinks = []
    for sink in cfg.get("sinks", []):
        sinks.append(
            {
                "block_address": int(sink["block_address"]),
                "callsite_address": int(sink["callsite_address"]),
                "sink_address": int(sink["sink_address"]),
                "sink_name": sink.get("sink_name", ""),
            }
        )
    return {
        "node_by_addr": node_by_addr,
        "edges": edges,
        "roots": roots,
        "sinks": sinks,
        "schema_version": cfg.get("schema_version", 1),
    }


def _build_cfg_graph(cfg_data) -> nx.DiGraph:
    """Build a real-CFG DiGraph from loaded sink_cfg.json data."""
    graph = nx.DiGraph()
    for addr in cfg_data["node_by_addr"]:
        graph.add_node(addr)
    for source, target, _kind in cfg_data["edges"]:
        graph.add_edge(source, target, weight=1.0)
    return graph


def _compute_scores_by_cfg(cfg_data, distance_weight: float):
    """Compute proximity/depth scores on the real CFG (plan §5.3-5.4).

    - distance_to_sink: multi-source Dijkstra from all sink blocks on the
      reversed graph (shortest number of edges to the nearest sink).
    - proximity(n) = 1 / (1 + raw_distance(n))  -- so nearer is higher.
    - depth: multi-source Dijkstra from roots on the original graph.
    - score(n) = depth_norm(n) + w * proximity(n).
    """
    graph = _build_cfg_graph(cfg_data)

    reverse_graph = graph.reverse(copy=False)
    sink_blocks = [s["block_address"] for s in cfg_data["sinks"]]
    sink_blocks = [s for s in sink_blocks if s in graph]
    sink_blocks = list(dict.fromkeys(sink_blocks))

    per_sink_maps = {}
    for sink in sink_blocks:
        per_sink_maps[sink] = nx.single_source_dijkstra_path_length(
            reverse_graph, sink, weight="weight"
        )

    distance_to_sink = {}
    nearest_sink_of = {}
    for sink, dist_map in per_sink_maps.items():
        for node, dist in dist_map.items():
            current = distance_to_sink.get(node)
            if current is None or dist < current:
                distance_to_sink[node] = dist
                nearest_sink_of[node] = sink

    depth = {}
    for root in cfg_data["roots"]:
        if root not in graph:
            continue
        depth_map = nx.single_source_dijkstra_path_length(graph, root, weight="weight")
        for node, dist in depth_map.items():
            current = depth.get(node)
            if current is None or dist > current:
                depth[node] = dist

    if depth:
        max_depth = max(depth.values())
    else:
        max_depth = 1.0
    if max_depth <= 0:
        max_depth = 1.0

    rows = []
    reachable_count = 0
    for addr, node in sorted(cfg_data["node_by_addr"].items()):
        raw_distance = distance_to_sink.get(addr)
        if raw_distance is None:
            continue
        reachable_count += 1
        proximity = 1.0 / (1.0 + float(raw_distance))
        depth_value = float(depth.get(addr, 0.0))
        depth_norm = depth_value / max_depth
        score = depth_norm + distance_weight * proximity
        rows.append(
            {
                "node": addr,
                "end_address": int(node.get("end_address", addr)),
                "nearest_sink": nearest_sink_of.get(addr, 0),
                "depth": depth_value,
                "normalized_depth": round(depth_norm, 6),
                "distance_to_sink": float(raw_distance),
                "sink_proximity": round(proximity, 6),
                "score": round(score, 6),
            }
        )

    rows.sort(key=lambda item: item["score"], reverse=True)
    return rows, reachable_count, len(cfg_data["node_by_addr"])


def _write_score_table(output_dir: str, rows: List[Dict[str, float]], cfg_source: str = "pseudo", distance_weight: float = 1.0, node_count: int = 0, reachable_count: int = 0) -> Tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "sink_distance_scores.json")
    csv_path = os.path.join(output_dir, "sink_distance_scores.csv")

    # Metadata-object output (plan §5.5); the fuzzer loader also accepts the
    # legacy top-level array, so we keep the object for the paper experiment.
    payload = {
        "schema_version": 1,
        "cfg_source": cfg_source,
        "distance_weight": distance_weight,
        "node_count": node_count if node_count else len(rows),
        "reachable_node_count": reachable_count if reachable_count else len(rows),
        "scores": rows,
    }

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)

    with open(csv_path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["node", "nearest_sink", "depth", "distance_to_sink", "normalized_depth", "sink_proximity", "score"]
        )
        for item in rows:
            writer.writerow(
                [
                    hex(int(item["node"])),
                    hex(int(item["nearest_sink"])),
                    item["depth"],
                    item["distance_to_sink"],
                    item.get("normalized_depth", ""),
                    item.get("sink_proximity", ""),
                    item["score"],
                ]
            )

    return json_path, csv_path


def _print_top_rows(rows, limit=10):
    """Print the top-scoring nodes as a hex address table."""
    print("[+] Top {0} high-priority nodes:".format(min(limit, len(rows))))
    for item in rows[:limit]:
        print(
            "    node={} sink={} depth={} dis={} prox={} score={}".format(
                hex(int(item["node"])),
                hex(int(item["nearest_sink"])),
                item["depth"],
                item["distance_to_sink"],
                item.get("sink_proximity", ""),
                round(item["score"], 4),
            )
        )


def main():
    parser = argparse.ArgumentParser(
        description="Compute sink-oriented block scores with Dijkstra on reversed CFG."
    )
    parser.add_argument(
        "--sink-scope",
        default="sink_scope_addr.txt",
        help="Path to sink scope range file generated by Get_SinkFunc.py",
    )
    parser.add_argument(
        "--cfg",
        default=None,
        help="Path to real-CFG sink_cfg.json (preferred source; enables proximity scoring)",
    )
    parser.add_argument(
        "--distance-weight",
        type=float,
        default=1.0,
        help="Weight multiplier w on sink proximity in score (default: 1.0)",
    )
    parser.add_argument(
        "--allow-pseudo-cfg",
        action="store_true",
        help="Enable pseudo-CFG fallback built from address ranges (paper experiments must use --cfg)",
    )
    parser.add_argument(
        "--block-step",
        type=int,
        default=4,
        help="Pseudo basic-block step when expanding address ranges (default: 4)",
    )
    parser.add_argument(
        "--indirect-edges",
        type=int,
        default=0,
        help="Indirect edge count for w calculation (default: 0 -> w=1)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to save score tables (default: same directory as --cfg / --sink-scope)",
    )
    args = parser.parse_args()

    # Determine output directory: --output-dir wins, else next to input.
    if args.output_dir:
        output_dir = args.output_dir
    else:
        base = args.cfg or args.sink_scope
        base_dir = os.path.dirname(os.path.abspath(base))
        output_dir = base_dir if base_dir else "."

    cfg_data = _load_cfg(args.cfg) if args.cfg else None
    if cfg_data is not None:
        rows, reachable_count, node_count = _compute_scores_by_cfg(
            cfg_data, max(args.distance_weight, 0.0)
        )
        json_path, csv_path = _write_score_table(
            output_dir,
            rows,
            cfg_source="ida",
            distance_weight=max(args.distance_weight, 0.0),
            node_count=node_count,
            reachable_count=reachable_count,
        )
        print(f"[+] Real CFG loaded (schema v{cfg_data['schema_version']})")
        print(f"[+] Nodes={node_count} reachable_to_sink={reachable_count} "
              f"w={args.distance_weight}")
        print(f"[+] Score rows: {len(rows)}")
        print(f"[+] JSON: {json_path}")
        print(f"[+] CSV : {csv_path}")
        _print_top_rows(rows)
        return

    if not args.allow_pseudo_cfg:
        print(
            "[!] No --cfg provided (or sink_cfg.json unreadable) and --allow-pseudo-cfg "
            "not set; writing empty score table. Use --cfg for real proximity scores."
        )
        json_path, csv_path = _write_score_table(output_dir, [], cfg_source="pseudo")
        print(f"[+] Empty score tables written to: {json_path}, {csv_path}")
        return

    sink_ranges = _parse_sink_scope_ranges(args.sink_scope)
    if not sink_ranges:
        print(f"[!] No sink ranges found in {args.sink_scope}")
        json_path, csv_path = _write_score_table(output_dir, [])
        print(f"[+] Empty score tables written to: {json_path}, {csv_path}")
        return

    pr_regions, pr_region_exits, graph = _build_pseudo_cfg_from_ranges(sink_ranges, max(args.block_step, 1))
    rows, w = _compute_scores_by_paper(pr_regions, pr_region_exits, graph, max(args.indirect_edges, 0))
    json_path, csv_path = _write_score_table(output_dir, rows, cfg_source="pseudo")

    print(f"[+] Sink ranges loaded: {len(sink_ranges)}")
    print(f"[+] Pseudo-CFG nodes={graph.number_of_nodes()} edges={graph.number_of_edges()} w={w}")
    print(f"[+] Score rows: {len(rows)}")
    print(f"[+] JSON: {json_path}")
    print(f"[+] CSV : {csv_path}")
    _print_top_rows(rows)


if __name__ == "__main__":
    main()