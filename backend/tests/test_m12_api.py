"""
Tests for M12 FastAPI Backend.
Tests the API endpoints and integration with the orchestrator.
"""
import pytest
import os
import tempfile
import shutil
from fastapi.testclient import TestClient
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import the app
from securemailscope.api.main import app
from securemailscope.api.database import Base, get_db

# Create a test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_securemailscope.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def run_around_tests():
    # Setup
    Base.metadata.create_all(bind=engine)
    yield
    # Teardown
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

# Real PCAP fixture path
PCAP_FIXTURE = Path(__file__).parent / "robustness" / "fixtures" / "pcaps" / "clean_baseline.pcap"

def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database_connected"] is True


def test_capture_upload_invalid_type(client):
    """Test uploading invalid file type."""
    response = client.post("/analyze", files={"file": ("test.txt", b"test content", "text/plain")})
    assert response.status_code == 422


def test_capture_upload_file_too_large(client):
    """Test uploading file that exceeds size limit."""
    large_content = b"x" * (100 * 1024 * 1024 + 1)
    response = client.post("/analyze", files={"file": ("large.pcap", large_content, "application/octet-stream")})
    assert response.status_code == 413


def test_capture_upload_valid_pcap(client):
    """Test uploading a valid PCAP file."""
    if not PCAP_FIXTURE.exists():
        pytest.skip("Fixture not found")
    with open(PCAP_FIXTURE, "rb") as f:
        response = client.post("/analyze", files={"file": ("clean_baseline.pcap", f.read(), "application/octet-stream")})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["processing", "completed"]
    assert "capture_id" in data


def test_capture_retrieval(client):
    """Test retrieving capture details."""
    if not PCAP_FIXTURE.exists():
        pytest.skip("Fixture not found")
    with open(PCAP_FIXTURE, "rb") as f:
        upload_response = client.post("/analyze", files={"file": ("clean_baseline.pcap", f.read(), "application/octet-stream")})
    assert upload_response.status_code == 200
    capture_id = upload_response.json()["capture_id"]

    response = client.get(f"/captures/{capture_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["capture_id"] == capture_id


def test_get_nonexistent_capture(client):
    """Test retrieving non-existent capture."""
    response = client.get("/captures/non-existent-id")
    assert response.status_code == 404


def test_list_captures(client):
    """Test listing captures."""
    if not PCAP_FIXTURE.exists():
        pytest.skip("Fixture not found")
    with open(PCAP_FIXTURE, "rb") as f:
        content = f.read()
    client.post("/analyze", files={"file": ("test1.pcap", content, "application/octet-stream")})
    client.post("/analyze", files={"file": ("test2.pcap", content, "application/octet-stream")})

    response = client.get("/captures")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2


def test_get_capture_sessions(client):
    """Test listing sessions for a capture."""
    if not PCAP_FIXTURE.exists():
        pytest.skip("Fixture not found")
    with open(PCAP_FIXTURE, "rb") as f:
        upload_response = client.post("/analyze", files={"file": ("clean_baseline.pcap", f.read(), "application/octet-stream")})
    capture_id = upload_response.json()["capture_id"]

    response = client.get(f"/captures/{capture_id}/sessions")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_nonexistent_session(client):
    """Test getting non-existent session."""
    response = client.get("/sessions/non-existent-session-id")
    assert response.status_code == 404


def test_get_nonexistent_finding(client):
    """Test getting non-existent finding."""
    response = client.get("/findings/non-existent-finding-id")
    assert response.status_code == 404


def test_get_nonexistent_anomaly(client):
    """Test getting non-existent anomaly."""
    response = client.get("/anomalies/999999")
    assert response.status_code == 404


def test_get_nonexistent_posture(client):
    """Test getting non-existent posture."""
    response = client.get("/captures/non-existent-capture-id/posture")
    assert response.status_code == 404


def test_get_certificate(client):
    """Test getting certificate information."""
    response = client.get("/certificates")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_nonexistent_report(client):
    """Test getting non-existent report."""
    response = client.get("/reports/non-existent-report-id")
    assert response.status_code == 404


def test_api_e2e_workflow(client):
    """End-to-end test of the API workflow."""
    if not PCAP_FIXTURE.exists():
        pytest.skip("Fixture not found")
    with open(PCAP_FIXTURE, "rb") as f:
        upload_response = client.post("/analyze", files={"file": ("clean_baseline.pcap", f.read(), "application/octet-stream")})
    assert upload_response.status_code == 200
    capture_id = upload_response.json()["capture_id"]

    # Retrieve capture
    capture_response = client.get(f"/captures/{capture_id}")
    assert capture_response.status_code == 200
    assert capture_response.json()["analysis_status"] in ["pending", "processing", "completed"]
