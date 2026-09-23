"""tbsol - Solana incident explainer and fund tracer for TraceBrief.

TraceBrief turns a crypto theft into a report a victim can act on. This package
is the Solana part that explains *how* funds left a wallet (not only where they
went): delegate spends, token-account ownership changes, durable-nonce
transactions, wallet reassignment, closed accounts and poisoned addresses.

Everything here reads public chain data only. Nothing signs, nothing custodies.
"""

__version__ = "0.1.0"

from .model import Finding, Transfer, IncidentReport  # noqa: F401
