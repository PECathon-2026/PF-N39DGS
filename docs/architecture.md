# PrivacyLens Architecture

## Core Principle
"Compute what is sensitive locally. Reason globally only on sanitized data."

## Architectural Overview
PrivacyLens operates as a privacy-preserving AI browser agent and sanitization engine.
1. **Local Detection Engine**: Identifies PII, credentials, financial, and national ID data locally via regex, checksums, NLP (Presidio/spaCy), and OCR/computer vision (Tesseract/OpenCV).
2. **Sanitization Engine**: Replaces identified sensitive data with consistent, format-preserving or tokenized placeholders before sending context to external LLMs.
3. **Egress Gateway & Audit**: Ensures no raw sensitive text or images escape the local perimeter, logging irreversible SHA-256 prefixes and entity counts.
4. **Agent Execution Loop**: Translates sanitized user goals into deterministic browser actions (Playwright) while enforcing human-in-the-loop approval policies for destructive/high-risk actions.

