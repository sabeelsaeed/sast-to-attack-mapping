"""SAST-to-ATT&CK mapping pipeline.

Data flows one direction: ``SAST JSON -> normalize -> bridge
(authoritative | NLP fallback) -> enrich -> evaluate``.
"""

__version__ = "0.1.0"
