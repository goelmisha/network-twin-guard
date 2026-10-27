"""FastAPI application entry point.

Run with:

    uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000

Exception handling strategy:
    * :class:`~app.core.exceptions.TwinError` subclasses map to their declared
      HTTP status and a machine-readable :class:`ErrorResponse`.
    * Pydantic validation failures map to 422 with the same envelope shape, so
      the dashboard has a single error contract to branch on.
    * Anything unexpected is logged with a stack trace and returned as a generic
      500 envelope; internal details never leak to the client.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .api.router import API_PREFIX, api_router
from .config import Settings, get_settings
from .core.exceptions import TopologyModelError, TwinError
from .models.errors import ErrorResponse

logger = logging.getLogger("corporate_twin")

DESCRIPTION = """
**Pre-Change Network Digital Twin & Attack-Path Risk Analysis Platform.**

Validate a network security change *before* it reaches production. The platform
captures a baseline of the branch office (routing, reachability and firewall
policy), applies a candidate change to a copy of that model, re-solves multi-hop
reachability across the topology graph, and reports exactly what opened, what
closed, and how far an attacker could travel.

Capabilities:

* **Snapshot engine** -- baseline capture from live containers or from the
  declarative model when the lab is torn down.
* **Differential engine** -- before/after policy and reachability deltas.
* **Attack-path & blast-radius analysis** -- criticality-weighted exposure with a
  0-100 composite risk score.
* **Compliance controls** -- default-deny posture, crown-jewel exposure,
  management-plane reachability and legacy protocol checks.
* **Safe rollback** -- restore the baseline logically, and re-push it to live
  containers when the lab is deployed.
"""


def _configure_logging(settings: Settings) -> None:
    """Configure root logging once, without clobbering host configuration."""
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logger.debug("Logging initialised with state dir %s", settings.state_dir)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Prepare directories and warm the model cache on startup."""
    settings = get_settings()
    settings.ensure_directories()
    service = application.state.twin_service

    try:
        model = service.load_model()
        logger.info(
            "Loaded topology '%s' with %d nodes, %d links and %d probe flows.",
            model.topology.lab_name,
            len(model.topology.nodes),
            len(model.topology.links),
            len(model.topology.probe_flows),
        )
    except TopologyModelError as exc:
        # Startup must not crash: the health endpoint reports the problem and the
        # operator can fix the model file without restarting a failing container.
        logger.error("Topology/model failed to load: %s", exc.detail)

    status_payload = await service.runtime_status()
    logger.info("Runtime mode: %s -- %s", status_payload.runtime_mode.value, status_payload.detail)
    yield
    logger.info("Shutting down corporate-twin backend.")


def create_app() -> FastAPI:
    """Build the FastAPI application.

    Returns:
        A fully configured application instance.
    """
    settings = get_settings()
    _configure_logging(settings)

    from .services import get_twin_service

    application = FastAPI(
        title="Corporate Twin -- Pre-Change Network Digital Twin",
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    application.state.twin_service = get_twin_service()

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.exception_handler(TwinError)
    async def handle_twin_error(_: Request, exc: TwinError) -> JSONResponse:
        """Translate a domain failure into its declared HTTP status."""
        logger.warning("Domain error %s: %s", exc.code, exc.detail)
        return JSONResponse(status_code=exc.http_status, content=exc.to_response().model_dump())

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        """Normalise request validation failures into the standard envelope."""
        problems = [
            {
                "location": ".".join(str(part) for part in error.get("loc", ())),
                "message": error.get("msg", "invalid value"),
                "type": error.get("type", "value_error"),
            }
            for error in exc.errors()
        ]
        envelope = ErrorResponse(
            code="validation_error",
            detail="Request payload failed validation.",
            context={"problems": problems},
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=envelope.model_dump(),
        )

    @application.exception_handler(Exception)
    async def handle_unexpected(_: Request, exc: Exception) -> JSONResponse:
        """Log and mask unexpected failures."""
        logger.exception("Unhandled error: %s", exc)
        envelope = ErrorResponse(
            code="internal_error",
            detail="An unexpected internal error occurred. Check the backend logs.",
            context={"exception_type": type(exc).__name__},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=envelope.model_dump(),
        )

    @application.get("/", tags=["system"], summary="Service banner")
    async def root() -> dict[str, str]:
        """Return a short banner describing the service and its entry points."""
        return {
            "service": "corporate-twin",
            "version": __version__,
            "api": API_PREFIX,
            "docs": "/docs",
            "health": f"{API_PREFIX}/health",
        }

    application.include_router(api_router)
    return application


app = create_app()


def main() -> None:  # pragma: no cover - CLI convenience
    """Run the API with uvicorn (``python -m app.main``)."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
