from __future__ import annotations

from collections import OrderedDict
import random

from angerona.modules.provenance_graph import ProvenanceGraph


class _PreviousEvictionGraph(ProvenanceGraph):
    """Reference the prior scan semantics for bounded differential churn."""

    def _drop_node_links(self, node_id, retired_node):
        for child in tuple(self.edges.get(node_id, ())):
            self._discard_edge(node_id, child)
        for parent in tuple(self.parents.get(node_id, ())):
            self._discard_edge(parent, node_id)
        self._discard_pid_node(self._node_pid(retired_node), node_id)
        for pid, current in tuple(self._latest_pid_node.items()):
            if current != node_id:
                continue
            candidates = [
                (float(node.get("ts", 0.0)), candidate)
                for candidate, node in self.nodes.items()
                if node.get("kind") == "PROC"
                and (node.get("meta") or {}).get("pid") == pid
            ]
            if candidates:
                self._latest_pid_node[pid] = max(candidates)[1]
            else:
                self._latest_pid_node.pop(pid, None)


def test_eviction_matches_previous_lifetime_selection_during_bounded_churn():
    graph = ProvenanceGraph(max_nodes=24, max_edges=12)
    reference = _PreviousEvictionGraph(max_nodes=24, max_edges=12)
    randomizer = random.Random(147)
    for index in range(600):
        details = {"pid": randomizer.randrange(10, 20)}
        if index % 3:
            details["process_create_time"] = randomizer.randrange(1, 10)
        if index % 4:
            details["ppid"] = randomizer.randrange(10, 20)
        if index % 5:
            details["path"] = f"C:/synthetic/{index % 31}.bin"
        stamp = float(index // 3)  # Include timestamp ties.
        graph.ingest("synthetic", "event", details, stamp)
        reference.ingest("synthetic", "event", details, stamp)
        assert graph.nodes == reference.nodes
        assert graph.edges == reference.edges
        assert graph.parents == reference.parents
        assert graph._latest_pid_node == reference._latest_pid_node
        assert len(graph.nodes) <= graph.max_nodes
        assert len(graph._edge_order) <= graph.max_edges
        expected = {}
        for node_id, node in graph.nodes.items():
            if node["kind"] == "PROC":
                expected.setdefault(node["meta"]["pid"], set()).add(node_id)
        assert graph._pid_nodes == expected


def test_latest_lifetime_eviction_preserves_timestamp_and_id_tie_break():
    graph = ProvenanceGraph(max_nodes=3)
    identities = []
    for birth in (10, 20, 30):
        graph.ingest("sensor", "spawn", {"pid": 42, "process_create_time": birth}, 7.0)
        identities.append(graph._latest_pid_node[42])
    # Make the currently selected lifetime oldest in recency while keeping the
    # two fallback timestamps equal. Neither direct refresh changes selection.
    for node_id in identities[:2]:
        graph.add_node(node_id, "PROC", "retained", 7.0, pid=42)
    graph.add_node("FIM:new", "FIM", "artifact", 8.0)
    assert identities[2] not in graph.nodes
    assert graph._latest_pid_node[42] == max(identities[:2])
    assert graph._pid_nodes[42] == set(identities[:2])


def test_unique_pid_eviction_does_not_scan_unrelated_nodes_or_pid_index():
    class NoItemsOrderedDict(OrderedDict):
        def items(self):
            raise AssertionError("full node scan while evicting one process")

    class NoItemsDict(dict):
        def items(self):
            raise AssertionError("full PID scan while evicting one process")

    graph = ProvenanceGraph(max_nodes=8)
    for pid in range(8):
        graph.ingest("sensor", "spawn", {"pid": pid, "process_create_time": 1}, 1.0)
    graph.nodes = NoItemsOrderedDict(graph.nodes)
    graph._latest_pid_node = NoItemsDict(graph._latest_pid_node)
    graph.ingest("sensor", "spawn", {"pid": 99, "process_create_time": 2}, 2.0)
    assert len(graph.nodes) == len(graph._pid_nodes) == len(graph._latest_pid_node) == 8
    assert 0 not in graph._latest_pid_node
    assert 0 not in graph._pid_nodes


def test_pid_index_tracks_metadata_updates_without_stale_members():
    graph = ProvenanceGraph(max_nodes=2)
    graph.add_node("PROC:custom", "PROC", "custom", 1.0, pid=1)
    graph.add_node("PROC:custom", "PROC", "custom", 2.0, pid=2)
    assert graph._pid_nodes == {2: {"PROC:custom"}}
    graph.add_node("FIM:a", "FIM", "a", 3.0)
    graph.add_node("FIM:b", "FIM", "b", 4.0)
    assert not graph._pid_nodes
