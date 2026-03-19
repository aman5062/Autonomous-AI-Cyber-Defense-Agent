# Module 05: Knowledge Graph

## Purpose
Attack relationship mapping — visualizes attack taxonomy, kill chains, CVE-to-software links, and mitigation techniques using NetworkX.

## Status
✅ Implemented

## Files
- `backend/analysis/knowledge_graph.py` — graph construction and query

## Graph Schema
- Nodes: AttackType, Vulnerability, Software, MitigationTechnique, AttackStage
- Edges: exploits, affects, mitigates, leads_to

## Technologies
- NetworkX (graph library)
- matplotlib (visualization export)

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with NetworkX graph and attack taxonomy |
