# Module 04: Threat Intelligence Engine (RAG)

## Purpose
External threat knowledge via RAG — CVE database, NVD feeds, OWASP data ingested into Qdrant vector DB for semantic retrieval.

## Status
✅ Implemented

## Files
- `backend/intelligence/cve_fetcher.py` — NVD API integration
- `backend/intelligence/threat_db.py` — threat intelligence store
- `backend/intelligence/embeddings.py` — bge-small-en-v1.5 embeddings
- `backend/analysis/rag_engine.py` — LangChain RAG pipeline

## Architecture
1. CVE/advisory documents ingested and chunked
2. Embedded via bge-small-en-v1.5
3. Stored in Qdrant
4. Semantic search retrieves relevant context for LLM

## Data Sources
- NVD API (nvd.nist.gov)
- OWASP Top 10
- CVE MITRE list

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with NVD integration and Qdrant RAG |
