# ADR-0001: Python stack, Postgres + NetworkX instead of Neo4j

- Status: accepted
- Date: 2026-11-10

## Context

The design doc lists FastAPI for the API, Neo4j as the graph store, and
NetworkX for min-cut on extracted subgraphs. Before the first line of code we
had to settle two things: the implementation language for the whole engine,
and whether a dedicated graph database is needed in v1.

The alternative language considered was Go (used in rj-karan/AegisFlow).

## Decision

**Python 3.12 for everything server-side.** FastAPI, Pydantic v2, SQLAlchemy,
Redis + RQ, NetworkX, boto3, the official `kubernetes` client, pySigma.
Tooling: `uv`, `ruff`, `mypy --strict`, `pytest` with coverage.

**No Neo4j and no Cytoscape in v1.** The graph is held in memory in NetworkX
and persisted as versioned JSON snapshots in PostgreSQL. The Next.js dashboard
comes later and reads snapshots from the API.

## Reasons

1. **The security tooling ecosystem is Python.** Every project we reuse rather
   than rebuild is Python: cloud-audit (AWS privilege-escalation paths),
   Cartography (collectors), pySigma (detection rules), CloudGoat (lab
   scenarios), boto3 (the only first-party SDK with full IAM simulator and
   Access Analyzer coverage). A Go engine would mean reimplementing or
   shelling out to all of them.
2. **Graph algorithms come free.** NetworkX ships `minimum_cut`,
   `all_simple_paths`, dominators and flow algorithms with a long test
   history. The path-engine step in the design is "extract a subgraph, run
   min-cut"; it never needed a graph database for that.
3. **Lab graphs are small.** The seeded lab has tens to low hundreds of nodes.
   A Neo4j container adds operational weight, a second query language and a
   licensing question for a student project, with no benefit at this scale.
   Snapshots in Postgres keep the "versioned snapshot per scan" property from
   the design.
4. **Same language as Concord and the evaluator.** One toolchain, one type
   checker, one test runner.

## Consequences

- The Neo4j and Cytoscape rows in `docs/design.md` are superseded. If v2
  needs Cartography-compatible storage, a Neo4j exporter can be added behind
  the same snapshot interface.
- The in-memory graph must be rebuilt from a snapshot on worker start. That is
  cheap at lab scale and is covered by a test.
- `mypy --strict` is a hard CI gate from the first code PR, so the dynamic
  language does not erode the "no edge without evidence" rule: edge metadata is
  enforced by Pydantic models, not by convention.
