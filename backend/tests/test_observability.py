from app.core.observability import MetricsRegistry, is_uuid
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_request_id_is_returned_and_metrics_do_not_include_query_values() -> None:
    response = client.get(
        "/api/v1/health?token=should-not-be-exported",
        headers={"X-Request-ID": "analyst-request-01"},
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "analyst-request-01"

    metrics = client.get("/api/v1/metrics")
    assert metrics.status_code == 200
    assert "redpath_http_requests_total" in metrics.text
    assert "should-not-be-exported" not in metrics.text
    assert "token" not in metrics.text


def test_invalid_request_id_is_replaced_with_uuid() -> None:
    response = client.get("/api/v1/health", headers={"X-Request-ID": "not valid"})

    assert response.status_code == 200
    assert is_uuid(response.headers["X-Request-ID"])


def test_metrics_registry_decrements_in_flight_and_uses_status_classes() -> None:
    registry = MetricsRegistry()
    registry.start_request()
    registry.finish_request("GET", "/api/v1/health", 200, 0.125)

    snapshot = registry.snapshot()
    assert snapshot["in_flight"] == 0
    assert snapshot["requests"][("GET", "/api/v1/health", "2xx")] == 1
    assert snapshot["duration_counts"][("GET", "/api/v1/health")] == 1
    assert 'status_class="2xx"' in registry.prometheus()
