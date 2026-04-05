# Module 06: LLM Analysis Engine

## Purpose
AI-powered attack analysis using local Ollama LLM — natural language explanations, code-level fix recommendations, severity assessment, RAG-augmented context.

## Status
✅ Implemented

## Files
- `backend/analysis/llm_analyzer.py` — Ollama API client + analysis pipeline
- `backend/analysis/prompts.py` — prompt templates per attack type

## Models
- llama3.2:3b (default, lightweight)
- llama3:8b (higher quality option)
- codellama:7b (code fix analysis)

## Output Format
```json
{
  "explanation": "...",
  "impact": "...",
  "mitigation": ["step1", "step2"],
  "code_fix": {"vulnerable": "...", "secure": "..."},
  "references": ["OWASP A03", "CVE-2023-xxxx"]
}
```

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with Ollama integration and RAG context injection |
