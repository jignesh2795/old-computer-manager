"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import router

API_VERSION = "1.0"


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    The application is intended for localhost use only.
    """
    app = FastAPI(
        title="Old Computer Manager API",
        description=(
            "Local read-only API for computer health reporting. "
            "This API is intended for localhost use only and does not "
            "expose any modification endpoints."
        ),
        version=API_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.include_router(router)

    @app.get("/health", tags=["health"])
    def health_check() -> dict[str, str]:
        """Minimal health check endpoint. Does not run discovery."""
        return {
            "status": "ok",
            "service": "old-computer-manager",
            "version": API_VERSION,
        }

    return app


app = create_app()
