# GovBind

This repository accompanies the GovBind project for Financial Cryptography and
Data Security 2027.

GovBind lets people prove limited facts from government-issued PDF documents
without revealing the complete document or giving a verifier access to the
government portal.

The protocol combines zkTLS provenance with a zero-knowledge proof of document
content. It works with existing HTTPS verification services and does not require
the issuer to modify its service or add a separately verifiable signature.

This repository contains two constructions:

- `basic-protocol/` binds zkTLS and content verification through a commitment
  to the complete response body.
- `optimized-protocol/` makes client-side proving practical for compressed PDFs
  by committing separately to private ranges, disclosing the remaining bytes,
  enforcing their exact partition, and proving claims over the compressed
  content while constraining DEFLATE decompression.

The prototype supports proofs of no overdue tax debt, bounded traffic
penalties, and residence city for documents returned by Türkiye's e-Devlet
verification services. In the paper evaluation, 72 proofs across 24 sessions
took 54–119 seconds to generate and 44–127 milliseconds to verify, with proof
sizes of 11–12 KiB.

GovBind is a research prototype. Private PDFs, witnesses, proof records, TLS
openings, session data, and benchmark source documents are not included in this
repository and must never be committed.
