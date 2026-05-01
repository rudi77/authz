"""Observability primitives: structured logging, Prometheus metrics, tracing.

Tracing is opt-in: instrumentation only fires if the
``opentelemetry-instrumentation-fastapi`` package is installed and the user
has called :func:`init_tracing`. We avoid hard-importing OTel so the base
service has no extra runtime cost.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

import structlog
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


def configure_logging(level: str = "INFO") -> None:
    """Wire structlog + stdlib logging into a single JSON-friendly pipeline."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ---- Metrics ----------------------------------------------------------------

# Custom registry so the test runner can reset between cases without touching
# the global default registry (which would persist across tests).
REGISTRY = CollectorRegistry()

DECISIONS_TOTAL = Counter(
    "authz_decisions_total",
    "Total authorization decisions evaluated.",
    ["application_id", "subject_type", "decision"],
    registry=REGISTRY,
)
DECISIONS_BY_REASON = Counter(
    "authz_decisions_by_reason_total",
    "Authorization decisions partitioned by reason.",
    ["application_id", "subject_type", "decision", "reason"],
    registry=REGISTRY,
)
DECISION_LATENCY = Histogram(
    "authz_decision_latency_seconds",
    "Latency of /v1/authorize and /v1/bulk-authorize handlers.",
    ["endpoint"],
    registry=REGISTRY,
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)
HTTP_REQUESTS_TOTAL = Counter(
    "authz_http_requests_total",
    "HTTP requests handled by the AuthZ service.",
    ["method", "path", "status"],
    registry=REGISTRY,
)
HTTP_REQUEST_LATENCY = Histogram(
    "authz_http_request_duration_seconds",
    "HTTP request handler duration.",
    ["method", "path"],
    registry=REGISTRY,
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)


def record_decision(
    *, application_id: str, subject_type: str, decision: str, reason: str
) -> None:
    DECISIONS_TOTAL.labels(application_id, subject_type, decision).inc()
    DECISIONS_BY_REASON.labels(application_id, subject_type, decision, reason).inc()


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


# ---- Middleware -------------------------------------------------------------


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Bind a request_id to structlog and record HTTP metrics."""

    async def dispatch(self, request: Request, call_next: Callable[..., Any]):
        request_id = request.headers.get("X-Request-Id") or _new_request_id()
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            elapsed = time.perf_counter() - start
            HTTP_REQUEST_LATENCY.labels(request.method, request.url.path).observe(elapsed)
            HTTP_REQUESTS_TOTAL.labels(request.method, request.url.path, "500").inc()
            raise
        elapsed = time.perf_counter() - start
        HTTP_REQUEST_LATENCY.labels(request.method, request.url.path).observe(elapsed)
        HTTP_REQUESTS_TOTAL.labels(
            request.method, request.url.path, str(response.status_code)
        ).inc()
        response.headers["X-Request-Id"] = request_id
        return response


def _new_request_id() -> str:
    import uuid

    return uuid.uuid4().hex


# ---- Optional OTel ----------------------------------------------------------


def init_tracing(service_name: str = "authz-service") -> None:
    """Best-effort OpenTelemetry setup.

    Loads the OTel exporter from environment variables (OTEL_EXPORTER_OTLP_*).
    Silently returns if OTel libs aren't installed — instrumentation is opt-in.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,  # type: ignore[no-redef]
            )

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
    except ImportError:
        return


def instrument_fastapi(app) -> None:
    """Attach FastAPI + SQLAlchemy auto-instrumentation if libs available."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except ImportError:
        pass
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

        SQLAlchemyInstrumentor().instrument()
    except ImportError:
        pass
