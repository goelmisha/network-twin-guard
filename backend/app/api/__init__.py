"""HTTP layer.

Controllers are intentionally thin: they validate input, delegate to
:mod:`app.services`, and translate domain exceptions into HTTP responses via the
handlers registered in :mod:`app.main`.
"""

from .router import api_router

__all__ = ["api_router"]
