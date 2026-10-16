#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Feedback-driven greybox fuzzing helpers (plan: CFG-guided fuzzing §6-§10).

Fuzzer.py routes to this module when both --distance-file and --qemu-log are
given.  It implements:

  DistanceIndex      -- load sink_distance_scores.json (metadata object or the
                        legacy top-level array) and interval-map a QEMU trace PC
                        onto a static CFG block [address, end_address).
  TraceWindowReader  -- byte-window slice of the QEMU exec log taken around one
                        request; rotation/truncation is detected instead of
                        crashing the loop.
  CoverageTracker    -- global block/edge coverage plus per-edge hit counts.
  MutationDictionary -- parameter/global/external/builtin tokens and taint
                        value templates (section 7).
  Seed / CorpusScheduler -- structured corpus, interesting decision, energy
                        allocation and priority-weighted selection (section 8).
  GuidedFuzzer       -- the full loop: select seed, mutate, send, read the trace
                        window, update coverage, record feedback, write
                        result.json + fuzzing_summary.json.

Encoding: UTF-8 throughout.  Vendored trees are not touched.
"""

import bisect
import hashlib
import json
import os
import random
import re
import subprocess
import time

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Tunable constants (plan sections 8.4/8.5) -- single source of truth so the
# paper experiment and the regression tests share the same numbers.
# ---------------------------------------------------------------------------
BASE_ENERGY = 8.0
MIN_ENERGY = 1
MAX_ENERGY = 64
ALPHA_DISTANCE = 1.0          # weight on distance bonus in priority
BETA_RARITY = 1.0             # weight on edge rarity in priority
EXPLORATION_FRACTION = 0.2    # 20% uniform exploration (section 8.5)
AGING_MAX_BONUS = 0.5
AGING_PER_ELAPSED = 0.001     # per execution since last selection
MAX_CONSECUTIVE_MUTATIONS = 20
MAX_INITIAL_CORPUS = 100      # cap on the deterministic start corpus
DETERMINISTIC_DICT_SEEDS_PER_PARAM = 3

TAINT_TAG_PLACEHOLDER = "{tag}"

# Plan section 7.2: "{value}" is substituted with a dictionary/boundary token
# at mutation time; "{tag}" stays unresolved until the request is sent so a
# unique tag is generated fresh per execution (section 7.2 requirement).
VALUE_TEMPLATES = [
    "{tag}",
    "{value}{tag}",
    "{tag}{value}",
    "{value}:{tag}",
]

BOUNDARY_VALUES = [
    "",
    "0",
    "1",
    "-1",
    "65535",
    "4294967295",
    "A" * 32,
    "A" * 256,
    "A" * 1024,
    "%s%s%s%s%s%s%s%s",
    "%n",
    "0x41414141",
]


class DistanceIndex:
    """Load the distance table and map trace PCs onto static blocks.

    Accepts both the metadata-object format (plan section 5.5) and the legacy
    top-level array.  Blocks are matched by interval [address, end_address) so
    a QEMU TB PC that lands inside a basic block maps to that block even when
    it is not the exact start address (section 6.3, "interval mapping").
    """

    def __init__(self, path: Optional[str] = None, data=None):
        self._rows: List[Dict[str, Any]] = []
        self._by_node: Dict[int, Dict[str, Any]] = {}
        self._interval_starts: List[int] = []
        self.schema_version: Optional[int] = None
        self.cfg_source: Optional[str] = None
        self.distance_weight: Optional[float] = None
        if path is not None:
            self.load(path)
        elif data is not None:
            self.load_dict(data)

    def load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as file:
            self.load_dict(json.load(file))

    def load_dict(self, data) -> None:
        if isinstance(data, dict) and isinstance(data.get("scores"), list):
            self.schema_version = data.get("schema_version")
            self.cfg_source = data.get("cfg_source")
            self.distance_weight = data.get("distance_weight")
            rows = data["scores"]
        elif isinstance(data, list):
            rows = data
        else:
            raise ValueError(
                "distance table must be a list or an object with 'scores' list"
            )

        self._rows = []
        self._by_node = {}
        for row in rows:
            try:
                node = int(row.get("node"))
            except (TypeError, ValueError):
                continue
            try:
                end = int(row.get("end_address", node))
            except (TypeError, ValueError):
                end = node
            if end <= node:
                end = node + 1
            dist = row.get("distance_to_sink")
            score = row.get("score")
            entry = {
                "node": node,
                "end": end,
                "row": row,
                "distance": float(dist) if dist is not None else None,
                "score": float(score) if score is not None else None,
            }
            self._rows.append(entry)
            self._by_node[node] = entry
        # Sort by start address so bisect can locate the containing interval.
        self._rows.sort(key=lambda e: e["node"])
        self._interval_starts = [e["node"] for e in self._rows]

    @property
    def node_count(self) -> int:
        return len(self._by_node)

    def map_pc(self, pc: int):
        """Return the interval entry whose half-open range contains pc, or None."""
        if not self._interval_starts:
            return None
        idx = bisect.bisect_right(self._interval_starts, pc) - 1
        if idx < 0:
            return None
        entry = self._interval_starts[idx]
        entry_obj = self._rows[idx]
        if pc < entry_obj["end"]:
            return entry_obj
        return None

    def distance_of(self, pc: int) -> Optional[float]:
        entry = self.map_pc(pc)
        return entry["distance"] if entry is not None else None

    def score_of(self, pc: int) -> Optional[float]:
        entry = self.map_pc(pc)
        return entry["score"] if entry is not None else None


class TraceWindowReader:
    """Byte-window slice of a QEMU exec log around one HTTP request.

    The caller records the log position before sending the request, then calls
    read_window() after the response has settled.  File rotation or truncation
    is detected and reported as feedback-invalid instead of aborting the loop.
    """

    # Regexes compatible with the exec-log line shapes in the wild, e.g.
    #   exec_tb tb:0x... pc=0x00401a80        (afl-qemu-trace / FirmAgent tracing)
    #   Trace 0: 0x7fffe8035440 [00000000/0040565c/0xa2]   (Greenhouse/gh3fuzz
    #     real firmware logs: the guest PC is the slash-delimited middle field)
    #   IN: 0x00401a80  /  0x00401a80:
    PC_PATTERNS = [
        re.compile(r"pc=0x([0-9a-fA-F]+)"),
        # Fuzzing-SA has three fields; ghqemu5 also appends tb->cflags.
        re.compile(r"\[[0-9a-fA-F]{4,16}/([0-9a-fA-F]{4,16})/(?:0x)?[0-9a-fA-F]{2,16}(?:/(?:0x)?[0-9a-fA-F]{2,16})?\]"),
        re.compile(r"(?:^|\s)(?:IN:\s*)?0x([0-9a-fA-F]{6,})(?:\s|:)", re.MULTILINE),
    ]

    def __init__(self, log_path: str, settle: float = 0.3):
        self.log_path = log_path
        self.settle = settle
        self._inode: Optional[int] = None
        self._start_offset: int = 0
        self._carry: bytes = b""

    def start_window(self) -> bool:
        """Record inode + byte offset just before the request is sent."""
        try:
            st = os.stat(self.log_path)
        except OSError:
            self._inode = None
            self._start_offset = 0
            return False
        self._inode = st.st_ino
        self._start_offset = st.st_size
        return True

    @staticmethod
    def _extract_pc(line: str) -> Optional[int]:
        for pattern in TraceWindowReader.PC_PATTERNS:
            match = pattern.search(line)
            if match:
                try:
                    return int(match.group(1), 16)
                except ValueError:
                    continue
        return None

    def read_window(
        self, before_snapshot: Optional[Callable[[], None]] = None
    ) -> Tuple[bool, List[int], Dict[str, Any]]:
        """Return (valid, pcs, meta).  pcs have consecutive duplicates removed.

        A False return means the feedback for this request must be treated as
        invalid (truncation / rotation / missing log) -- section 6.3.
        """
        if self._inode is None:
            return False, [], {"error": "no-start-window"}
        try:
            st = os.stat(self.log_path)
        except OSError:
            return False, [], {"error": "missing-log"}
        if st.st_ino != self._inode:
            self._carry = b""
            return False, [], {"error": "rotated"}
        if st.st_size < self._start_offset:
            self._carry = b""
            return False, [], {"error": "truncated"}

        if self.settle:
            time.sleep(self.settle)
        if before_snapshot:
            before_snapshot()

        try:
            st = os.stat(self.log_path)
        except OSError:
            return False, [], {"error": "missing-log-after-settle"}
        if st.st_ino != self._inode:
            self._carry = b""
            return False, [], {"error": "rotated-during-settle"}
        if st.st_size < self._start_offset:
            self._carry = b""
            return False, [], {"error": "truncated-during-settle"}

        end = st.st_size
        if end <= self._start_offset:
            return True, [], {"window_bytes": 0, "byte_start": self._start_offset, "byte_end": end}

        start = self._start_offset
        with open(self.log_path, "rb") as file:
            file.seek(start)
            raw = file.read(end - start)

        # Carry-buffer line alignment: a prior window may have ended mid-line.
        # Prepend the carried partial line so a torn boundary never drops an
        # address, and keep the (possibly partial) final line for the next
        # window (section 6.3).
        text = self._carry + raw
        lines = text.split(b"\n")
        self._carry = lines.pop(-1)

        pcs: List[int] = []
        for raw_line in lines:
            line = raw_line.decode("utf-8", errors="ignore")
            pc = self._extract_pc(line)
            if pc is not None:
                pcs.append(pc)

        # Filter consecutive duplicates (section 6.3 step 7) -- a loop re-fires
        # the same TB repeatedly and must not inflate block/edge counts.
        deduped: List[int] = []
        prev = None
        for pc in pcs:
            if pc != prev:
                deduped.append(pc)
                prev = pc

        self._start_offset = end
        return True, deduped, {"window_bytes": len(raw), "byte_start": start, "byte_end": end}


class IdlePauseController:
    """Suspend a traced container between HTTP requests to stop idle logging."""

    def __init__(self, container: str):
        self.container = container
        self.paused: Optional[bool] = None

    def _docker(self, *args: str) -> str:
        result = subprocess.run(
            ["docker", *args, self.container], capture_output=True, text=True,
            timeout=20, check=False,
        )
        if result.returncode:
            raise RuntimeError(
                "docker {} {} failed: {}".format(
                    args[0], self.container, result.stderr.strip()
                )
            )
        return result.stdout.strip()

    def ensure_paused(self) -> None:
        state = self._docker("inspect", "--format", "{{.State.Paused}}")
        if state not in ("true", "false"):
            raise RuntimeError("unexpected Docker paused state: {!r}".format(state))
        self.paused = state == "true"
        self.pause()

    def pause(self) -> None:
        if self.paused is False:
            self._docker("pause")
            self.paused = True

    def resume(self) -> None:
        if self.paused is True:
            self._docker("unpause")
            self.paused = False

    def release(self) -> None:
        self.resume()


class CoverageTracker:
    """Global block/edge coverage and per-edge hit counts (sections 8.3/8.4)."""

    def __init__(self):
        self.blocks: Set[int] = set()
        self.edges: Set[Tuple[int, int]] = set()
        self.edge_hits: Dict[Tuple[int, int], int] = {}

    def observe(
        self, block_ids: List[int], edge_ids: List[Tuple[int, int]]
    ) -> Tuple[int, int, int, int]:
        """Register a trace; returns (new_blocks, new_edges, trace_blocks, trace_edges)."""
        trace_blocks = set(block_ids)
        trace_edges = set(edge_ids)
        new_blocks = len(trace_blocks - self.blocks)
        new_edges = len(trace_edges - self.edges)
        self.blocks |= trace_blocks
        self.edges |= trace_edges
        for edge in trace_edges:
            self.edge_hits[edge] = self.edge_hits.get(edge, 0) + 1
        return new_blocks, new_edges, len(trace_blocks), len(trace_edges)

    def rarity_bonus(self, edge_ids: List[Tuple[int, int]]) -> float:
        """mean(1 / hit_count(edge)) over the unique edges of a trace."""
        unique = set(edge_ids)
        if not unique:
            return 0.0
        total = 0.0
        for edge in unique:
            hits = self.edge_hits.get(edge, 1)
            total += 1.0 / hits
        return total / len(unique)


class MutationDictionary:
    """Dictionary tokens plus taint value templates (section 7).

    Priority for picking a token: parameter-specific > JSON global > external
    AFL-style dictionary file > builtin boundary values (section 7.1).
    """

    def __init__(self):
        self.global_values: List[str] = []
        self.parameter_values: Dict[str, List[str]] = {}
        self.external_values: List[str] = []

    @classmethod
    def from_json(cls, data, dictionary_file: Optional[str] = None) -> "MutationDictionary":
        self = cls()
        if isinstance(data, dict):
            dictionary = data.get("dictionary", {})
            if isinstance(dictionary, dict):
                global_values = dictionary.get("global_values", [])
                if isinstance(global_values, list):
                    self.global_values = [str(v) for v in global_values]
                parameter_values = dictionary.get("parameter_values", {})
                if isinstance(parameter_values, dict):
                    for key, values in parameter_values.items():
                        if isinstance(values, list):
                            self.parameter_values[str(key)] = [str(v) for v in values]
        if dictionary_file:
            self.external_values = self._read_afl_dict(dictionary_file)
        return self

    @staticmethod
    def _read_afl_dict(path: str) -> List[str]:
        values: List[str] = []
        if not os.path.exists(path):
            return values
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith('"') and stripped.endswith('"') and not stripped.startswith("="):
                    inner = stripped[1:-1]
                elif "=" in stripped:
                    _name, _, rest = stripped.partition("=")
                    if rest.startswith('"') and rest.endswith('"'):
                        inner = rest[1:-1]
                    elif rest:
                        inner = rest
                    else:
                        continue
                else:
                    continue
                values.append(inner)
        return values

    def values_for(self, param: str) -> List[str]:
        if param in self.parameter_values and self.parameter_values[param]:
            return self.parameter_values[param]
        if self.global_values:
            return self.global_values
        if self.external_values:
            return self.external_values
        return BOUNDARY_VALUES

    def pick_value(self, param: str, rng: random.Random) -> str:
        values = self.values_for(param)
        return rng.choice(values)


@dataclass
class Seed:
    """Structured corpus item (plan section 8.1)."""

    seed_id: Optional[int]
    api_url: str
    method: str
    taint_param: Optional[str]
    value_template: str
    payload_template: Dict[str, str] = field(default_factory=dict)
    parent_id: Optional[int] = None
    generation: int = 0
    best_score: float = 0.0
    min_distance: Optional[float] = None
    new_blocks: int = 0
    new_edges: int = 0
    executions: int = 0
    consecutive_mutations: int = 0
    budget_remaining: int = 1
    last_selected_execution: int = 0
    rotation_index: int = 0
    recent_edges: List[Tuple[int, int]] = field(default_factory=list)
    anomaly_seen: bool = False

    def payload_hash(self) -> str:
        normalized = json.dumps(
            self.payload_template, sort_keys=True, ensure_ascii=False
        )
        return hashlib.md5(normalized.encode("utf-8")).hexdigest()

    def resolve_payload(self, tag: str) -> Dict[str, str]:
        """Substitute the tag at send time; unique tags are born here (§7.2)."""
        resolved: Dict[str, str] = {}
        for key, value in self.payload_template.items():
            if isinstance(value, str) and TAINT_TAG_PLACEHOLDER in value:
                value = value.replace(TAINT_TAG_PLACEHOLDER, tag)
            resolved[key] = value
        return resolved


class CorpusScheduler:
    """Corpus bookkeeping: initial seeds, interesting decision, energy, select."""

    def __init__(
        self,
        random_seed: Optional[int] = None,
        distance_index: Optional[DistanceIndex] = None,
    ) -> None:
        self.seeds: List[Seed] = []
        self._payload_seen: Set[str] = set()
        # Keep the original value as experiment metadata.  random.Random.seed
        # is a bound method and must never be written to JSON directly.
        self.random_seed = random_seed
        self.rng = random.Random(random_seed)
        self.distance_index = distance_index
        self.best_distance: Optional[float] = None
        self.best_score: float = 0.0
        self.select_exploration = 0
        self.select_guided = 0

    @property
    def size(self) -> int:
        return len(self.seeds)

    def _next_seed_id(self) -> int:
        return len(self.seeds) + 1

    def build_initial(
        self,
        api_endpoints: List[str],
        parameters: List[str],
        method: str,
        dictionary: MutationDictionary,
        max_total: int = MAX_INITIAL_CORPUS,
    ) -> None:
        """Per-API x per-param tag-only seed, then deterministic dict seeds."""
        seeds: List[Seed] = []
        for api in api_endpoints:
            for param in parameters:
                payload = {p: "" for p in parameters}
                payload[param] = TAINT_TAG_PLACEHOLDER
                seeds.append(
                    Seed(
                        seed_id=None,
                        api_url=api,
                        method=method,
                        taint_param=param,
                        value_template=TAINT_TAG_PLACEHOLDER,
                        payload_template=payload,
                    )
                )

        for api in api_endpoints:
            for param in parameters:
                values = dictionary.values_for(param)
                for token in values[:DETERMINISTIC_DICT_SEEDS_PER_PARAM]:
                    payload = {p: "" for p in parameters}
                    # deterministic templates rotate through the 4 forms
                    template = VALUE_TEMPLATES[len(seeds) % 4]
                    payload[param] = template.replace("{value}", token)
                    seeds.append(
                        Seed(
                            seed_id=None,
                            api_url=api,
                            method=method,
                            taint_param=param,
                            value_template=template,
                            payload_template=payload,
                        )
                    )

        # Cap the corpus so API x param x value combination cannot explode.
        if len(seeds) > max_total:
            seeds = seeds[:max_total]

        self.seeds = []
        self._payload_seen = set()
        for seed in seeds:
            seed.seed_id = self._next_seed_id()
            self.seeds.append(seed)
            self._payload_seen.add(seed.payload_hash())

    def add(self, seed: Seed, reason: str) -> bool:
        seed.seed_id = self._next_seed_id()
        self.seeds.append(seed)
        self._payload_seen.add(seed.payload_hash())
        return True

    def offer(
        self,
        candidate: Seed,
        metrics: Dict[str, Any],
        parent: Optional[Seed],
        anomaly: bool,
    ) -> Tuple[bool, str]:
        """Interesting decision (section 8.3), returning (add, reason)."""
        hashed = candidate.payload_hash()
        if hashed in self._payload_seen:
            return False, "dedup"
        new_blocks = metrics.get("new_blocks", 0)
        new_edges = metrics.get("new_edges", 0)
        distance_improved = metrics.get("distance_improved", False)
        max_target_score = metrics.get("max_target_score")
        if new_edges > 0 or new_blocks > 0:
            return True, "coverage"
        if distance_improved:
            return True, "distance"
        if parent is not None and max_target_score is not None:
            if max_target_score > parent.best_score + 0.05:
                return True, "score-gain"
        if anomaly:
            return True, "anomaly"
        return False, "no-feedback"

    def priority(self, seed: Seed, tracker: Optional[CoverageTracker]) -> float:
        """Section 8.4: 1 + coverage_bonus + alpha*distance_bonus + rarity_bonus."""
        coverage_bonus = min(seed.new_edges, 8) + 0.5 * min(seed.new_blocks, 8)
        distance_bonus = 0.0
        if seed.min_distance is not None:
            distance_bonus = 1.0 / (1.0 + seed.min_distance)
        rarity = 0.0
        if tracker is not None and seed.recent_edges:
            rarity = BETA_RARITY * tracker.rarity_bonus(seed.recent_edges)
        return 1.0 + coverage_bonus + ALPHA_DISTANCE * distance_bonus + rarity

    def _aging_bonus(self, seed: Seed, execution_index: int) -> float:
        elapsed = execution_index - seed.last_selected_execution
        return min(AGING_MAX_BONUS, max(0, elapsed) * AGING_PER_ELAPSED)

    def select(
        self, tracker: Optional[CoverageTracker], execution_index: int
    ) -> Optional[Seed]:
        """Weighted random selection with 20% uniform exploration (section 8.5)."""
        if not self.seeds:
            return None
        if self.rng.random() < EXPLORATION_FRACTION:
            self.select_exploration += 1
            return self.rng.choice(self.seeds)
        self.select_guided += 1
        weighted = []
        total = 0.0
        for seed in self.seeds:
            weight = self.priority(seed, tracker) + self._aging_bonus(
                seed, execution_index
            )
            weighted.append((weight, seed))
            total += weight
        hit = self.rng.uniform(0.0, total)
        cumulative = 0.0
        for weight, seed in weighted:
            cumulative += weight
            if hit <= cumulative:
                return seed
        return weighted[-1][1]

    def energy(self, seed: Seed, tracker: Optional[CoverageTracker]) -> int:
        """Section 8.4: clamp(round(BASE_ENERGY * priority))."""
        priority = self.priority(seed, tracker)
        energy = int(round(BASE_ENERGY * priority))
        return max(MIN_ENERGY, min(MAX_ENERGY, energy))


class GuidedFuzzer:
    """Full distance-guided feedback loop orchestrator (sections 9/10)."""

    def __init__(
        self,
        apifuzzer,
        distance_index: DistanceIndex,
        trace_reader: TraceWindowReader,
        iteration_limit: int = 1000,
        random_seed: Optional[int] = None,
        dictionary: Optional[MutationDictionary] = None,
        tag_mode: str = "constant",
        delay: float = 0.5,
        method: str = "POST",
        idle_controller: Optional[IdlePauseController] = None,
        trace_windows_out: Optional[str] = None,
    ) -> None:
        self.apifuzzer = apifuzzer
        self.distance_index = distance_index
        self.trace_reader = trace_reader
        self.iteration_limit = iteration_limit
        self.dictionary = dictionary or MutationDictionary()
        self.tag_mode = tag_mode
        self.delay = delay
        self.method = method.upper()
        self.idle_controller = idle_controller
        self.trace_windows_out = trace_windows_out
        self.tracker = CoverageTracker()
        self.corpus = CorpusScheduler(random_seed=random_seed, distance_index=distance_index)
        self.parameters: List[str] = []
        self.request_counter = 0
        self._results: List[Dict[str, Any]] = []
        self._mutation_op_counts: Dict[str, int] = {}
        self._mutation_op_yields: Dict[str, int] = {}
        self.best_distance_timeline: List[Dict[str, Any]] = []
        self.valid_feedback_count = 0
        self.total_executions = 0

    # -- request plumbing ---------------------------------------------------
    def _next_tag(self) -> str:
        self.request_counter += 1
        if self.tag_mode == "unique":
            return "{}_{}".format(self.apifuzzer.taint_tag, self.request_counter)
        return self.apifuzzer.taint_tag

    def _response_anomaly(self, analysis: Dict[str, Any]) -> bool:
        """HTTP anomaly is an auxiliary interesting signal, not coverage."""
        if analysis.get("potential_issue"):
            issue = analysis.get("issue_type")
            if issue in ("ServerError", "SlowResponse", "RequestError"):
                return True
        return False

    # -- mutation -----------------------------------------------------------
    def _mutation_ops(self) -> List[str]:
        return [
            "parameter_dictionary_replace",
            "param_value_rotate",
            "switch_taint_param",
            "tag_one_target",
            "boundary_mutation",
            "local_mutation",
        ]

    def _mutate(self, seed: Seed) -> Tuple[str, Seed]:
        rng = self.corpus.rng
        op = rng.choice(self._mutation_ops())
        child = Seed(
            seed_id=None,
            api_url=seed.api_url,
            method=seed.method,
            taint_param=seed.taint_param,
            value_template=seed.value_template,
            payload_template=dict(seed.payload_template),
            parent_id=seed.seed_id,
            generation=seed.generation + 1,
            rotation_index=seed.rotation_index,
        )

        parameters = self.parameters if self.parameters else [seed.taint_param]

        if op == "parameter_dictionary_replace":
            value = self.dictionary.pick_value(seed.taint_param, rng)
            template = rng.choice(VALUE_TEMPLATES)
            child.value_template = template
            child.payload_template[seed.taint_param] = template.replace("{value}", value)

        elif op == "param_value_rotate":
            values = self.dictionary.values_for(seed.taint_param)
            if values:
                idx = (seed.rotation_index + 1) % len(values)
                child.rotation_index = idx
                template = seed.value_template
                if "{value}" not in template:
                    template = "{value}{tag}"
                child.value_template = template
                child.payload_template[seed.taint_param] = template.replace(
                    "{value}", values[idx]
                )
            else:
                child.payload_template[seed.taint_param] = TAINT_TAG_PLACEHOLDER

        elif op == "switch_taint_param":
            candidates = [p for p in parameters if p != seed.taint_param]
            target = rng.choice(candidates) if candidates else seed.taint_param
            child.taint_param = target
            child.value_template = TAINT_TAG_PLACEHOLDER
            payload = {p: "" for p in parameters}
            for key, value in seed.payload_template.items():
                if key in payload:
                    payload[key] = value
            payload[target] = TAINT_TAG_PLACEHOLDER
            child.payload_template = payload

        elif op == "tag_one_target":
            target = rng.choice(parameters)
            child.taint_param = target
            child.value_template = TAINT_TAG_PLACEHOLDER
            payload = {p: seed.payload_template.get(p, "") for p in parameters}
            payload[target] = TAINT_TAG_PLACEHOLDER
            child.payload_template = payload

        elif op == "boundary_mutation":
            # Section 7.2: every template keeps {tag} so the taint value stays
            # traceable downstream; boundary values ride along as {value}.
            value = rng.choice(BOUNDARY_VALUES)
            template = "{value}{tag}"
            child.value_template = template
            child.payload_template[seed.taint_param] = template.replace("{value}", value)

        elif op == "local_mutation":
            target = seed.taint_param
            current = child.payload_template.get(target, "")
            if ":" in current:
                current = current.rsplit(":", 1)[0] + ":0000"
            elif current.isdigit():
                current += "0"
            else:
                current += rng.choice(["A", "a", "0", "1"])
            child.value_template = current
            child.payload_template[target] = current

        return op, child

    # -- trace mapping ------------------------------------------------------
    def _map_trace(self, pcs: List[int]) -> Tuple[List[Any], List[Tuple[Any, Any]]]:
        """Map PCs to block ids; unmapped PCs are kept as raw ids (§8.5)."""
        block_ids: List[Any] = []
        for pc in pcs:
            entry = self.distance_index.map_pc(pc)
            block_ids.append(entry["node"] if entry is not None else pc)
        edges: List[Tuple[Any, Any]] = []
        prev = None
        for block_id in block_ids:
            if prev is not None and block_id != prev:
                edges.append((prev, block_id))
            prev = block_id
        return block_ids, edges

    def _feedback_metrics(
        self, pcs: List[int], block_ids: List[Any], edges: List[Tuple[Any, Any]]
    ) -> Dict[str, Any]:
        new_blocks, new_edges, trace_blocks, trace_edges = self.tracker.observe(
            block_ids, edges
        )
        min_distance: Optional[float] = None
        max_target_score: Optional[float] = None
        for pc in pcs:
            entry = self.distance_index.map_pc(pc)
            if entry is None:
                continue
            if entry["distance"] is not None:
                if min_distance is None or entry["distance"] < min_distance:
                    min_distance = entry["distance"]
            if entry["score"] is not None:
                if max_target_score is None or entry["score"] > max_target_score:
                    max_target_score = entry["score"]

        distance_improved = False
        if min_distance is not None:
            if (
                self.corpus.best_distance is None
                or min_distance < self.corpus.best_distance
            ):
                self.corpus.best_distance = min_distance
                distance_improved = True
        coverage_improved = new_edges > 0 or new_blocks > 0
        if max_target_score is not None and max_target_score > self.corpus.best_score:
            self.corpus.best_score = max_target_score

        return {
            "valid": True,
            "trace_block_count": trace_blocks,
            "trace_edge_count": trace_edges,
            "new_blocks": new_blocks,
            "new_edges": new_edges,
            "min_distance_to_sink": min_distance,
            "max_target_score": max_target_score,
            "distance_improved": distance_improved,
            "coverage_improved": coverage_improved,
        }

    # -- main loop ----------------------------------------------------------
    def run_fuzzing(self) -> None:
        api_endpoints, self.parameters = self.apifuzzer.load_targets()
        if not api_endpoints:
            self.apifuzzer.logger.error("No API endpoints found for guided fuzzing")
            return

        self.corpus.build_initial(
            api_endpoints, self.parameters, self.method, self.dictionary
        )
        if self.trace_windows_out:
            with open(self.trace_windows_out, "w", encoding="utf-8"):
                pass
        if self.idle_controller:
            self.idle_controller.ensure_paused()

        loop_start = time.time()
        for iteration in range(self.iteration_limit):
            self.total_executions = iteration + 1
            seed = self.corpus.select(self.tracker, iteration)
            # Per-seed energy budget (section 8.4): a seed gets a fresh budget
            # of mutations when selected and burns one unit per execution.
            if seed.budget_remaining <= 0:
                seed.budget_remaining = self.corpus.energy(seed, self.tracker)

            op, child = self._mutate(seed)
            self._mutation_op_counts[op] = self._mutation_op_counts.get(op, 0) + 1

            tag = self._next_tag()
            payload = child.resolve_payload(tag)

            self.trace_reader.start_window()
            if self.idle_controller:
                self.idle_controller.resume()
            try:
                sent_at = self._utcnow()
                response_data = self.apifuzzer.send_request(
                    child.api_url, payload, child.method
                )
                received_at = self._utcnow()
                analysis = self.apifuzzer.analyze_response(response_data)
                valid, pcs, trace_meta = self.trace_reader.read_window(
                    before_snapshot=(self.idle_controller.pause
                                     if self.idle_controller else None)
                )
            finally:
                if self.idle_controller and self.idle_controller.paused is False:
                    self.idle_controller.pause()

            if self.trace_windows_out:
                window = {
                    "request_id": self.request_counter,
                    "sent_at": sent_at,
                    "byte_start": trace_meta.get("byte_start"),
                    "byte_end": trace_meta.get("byte_end"),
                    "invalid": not valid,
                }
                if not valid:
                    window["reason"] = trace_meta.get("error", "invalid_trace")
                with open(self.trace_windows_out, "a", encoding="utf-8") as out:
                    out.write(json.dumps(window) + "\n")

            anomaly = self._response_anomaly(analysis)
            metrics: Dict[str, Any] = {"valid": valid}
            if valid:
                block_ids, edges = self._map_trace(pcs)
                metrics = self._feedback_metrics(pcs, block_ids, edges)
                self.valid_feedback_count += 1
                child.recent_edges = edges[:]
                child.min_distance = metrics["min_distance_to_sink"]
                child.best_score = metrics["max_target_score"] or 0.0
                child.new_blocks = metrics["new_blocks"]
                child.new_edges = metrics["new_edges"]

                added, reason = self.corpus.offer(child, metrics, seed, anomaly)
                if added:
                    self.corpus.add(child, reason)
                    self._mutation_op_yields[op] = self._mutation_op_yields.get(op, 0) + 1
                else:
                    child.seed_id = None

            seed.executions += 1
            seed.consecutive_mutations += 1
            seed.last_selected_execution = iteration

            self.best_distance_timeline.append(
                {
                    "execution": iteration + 1,
                    "min_distance": metrics.get("min_distance_to_sink"),
                    "new_blocks": metrics.get("new_blocks", 0),
                    "new_edges": metrics.get("new_edges", 0),
                    "distance_improved": metrics.get("distance_improved", False),
                }
            )

            result = {
                "request_id": self.request_counter,
                "sent_at": sent_at,
                "received_at": received_at,
                "api_url": child.api_url,
                "method": child.method,
                "taint_param": child.taint_param,
                "taint_tag": tag,
                "post_payload": payload,
                "response": response_data,
                "analysis": analysis,
                "seed_id": child.seed_id,
                "parent_seed_id": child.parent_id,
                "generation": child.generation,
                "mutation": op,
                "feedback": metrics,
            }
            self._results.append(result)
            self.apifuzzer._append_stream_entry(result)

            if analysis.get("potential_issue"):
                self.apifuzzer.logger.warning(
                    "[!] Potential issue on {} param {}: {}".format(
                        child.api_url, child.taint_param, analysis.get("issue_type")
                    )
                )
            if iteration % 50 == 0 and iteration:
                self._flush_results()

            time.sleep(self.delay)
            # Consume the energy budget and reset it (plus the consecutive cap)
            # when it is exhausted (section 8.4). consecutive_mutations was
            # already incremented above, so it is only reset here, never
            # re-incremented.
            seed.budget_remaining -= 1
            if (
                seed.budget_remaining <= 0
                or seed.consecutive_mutations >= MAX_CONSECUTIVE_MUTATIONS
            ):
                seed.budget_remaining = self.corpus.energy(seed, self.tracker)
                seed.consecutive_mutations = 0

        self._flush_results()
        self._write_summary(loop_start)
        self.apifuzzer.logger.info(
            "Guided fuzzing done: {} iterations, {} valid feedback, corpus {}".format(
                self.total_executions, self.valid_feedback_count, self.corpus.size
            )
        )

    # -- output -------------------------------------------------------------
    def _utcnow(self) -> str:
        import datetime

        return datetime.datetime.utcnow().isoformat() + "Z"

    def _flush_results(self) -> None:
        result_path = self.apifuzzer._resolve_result_path()
        self.apifuzzer._flush_results(result_path, self._results)

    def _write_summary(self, loop_start: float) -> None:
        summary_path = os.path.join(
            os.path.dirname(os.path.abspath(self.apifuzzer.json_file)),
            "fuzzing_summary.json",
        )
        yield_map = {}
        for op in self._mutation_ops():
            yield_map[op] = {
                "executions": self._mutation_op_counts.get(op, 0),
                "interesting": self._mutation_op_yields.get(op, 0),
            }
        summary = {
            "schema_version": 1,
            "duration_seconds": round(time.time() - loop_start, 3),
            "total_executions": self.total_executions,
            "valid_feedback_count": self.valid_feedback_count,
            "cumulative_blocks": len(self.tracker.blocks),
            "cumulative_edges": len(self.tracker.edges),
            "corpus_size": self.corpus.size,
            "best_distance_to_sink": self.corpus.best_distance,
            "selection": {
                "exploration": self.corpus.select_exploration,
                "guided": self.corpus.select_guided,
            },
            "mutation_operators": yield_map,
            "random_seed": self.corpus.random_seed,
            "distance_index": {
                "schema_version": self.distance_index.schema_version,
                "cfg_source": self.distance_index.cfg_source,
                "distance_weight": self.distance_index.distance_weight,
                "node_count": self.distance_index.node_count,
            },
            "best_distance_timeline": self.best_distance_timeline,
        }
        with open(summary_path, "w", encoding="utf-8") as file:
            json.dump(summary, file, indent=2, ensure_ascii=False)
        self.apifuzzer.logger.info("Summary written to: {}".format(summary_path))
