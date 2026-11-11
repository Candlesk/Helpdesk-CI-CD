"""Request correlation, structured access logs and attack-pattern counters."""

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware

from app.detection import detect
from app.logging_utils import log_event
from app.metrics import record_request, record_suspicious


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id

        pattern = detect(request.url.query)
        if pattern:
            record_suspicious(pattern)
            log_event(
                "security.suspicious_request",
                level="warning",
                request_id=request_id,
                pattern=pattern,
                method=request.method,
                path=request.url.path,
                source_ip=request.client.host if request.client else None,
            )

        started = time.perf_counter()
        response = await call_next(request)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        response.headers["X-Request-ID"] = request_id
        record_request(response.status_code)

        session = request.scope.get("session") or {}
        log_event(
            "http.request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            status=response.status_code,
            latency_ms=latency_ms,
            user_id=session.get("user_id"),
            source_ip=request.client.host if request.client else None,
        )
        return response
