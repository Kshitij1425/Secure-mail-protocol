# SecureMailScope API. NOTE: not built/verified in the audit environment (no Docker available).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SECUREMAILSCOPE_DATABASE_URL=sqlite:////data/securemailscope.db \
    SECUREMAILSCOPE_UPLOAD_DIR=/data/uploads \
    SECUREMAILSCOPE_REPORTS_DIR=/data/reports

WORKDIR /app
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock
COPY securemailscope ./securemailscope
RUN pip install --no-cache-dir --no-deps . \
    && useradd --system --uid 10001 --home /data sms \
    && mkdir -p /data && chown sms /data

USER sms
VOLUME ["/data"]
EXPOSE 8000
# Inside the container the API listens on all container interfaces; publish it only
# to the host loopback (see docker-compose.yml). The API has no authentication.
CMD ["python", "-m", "uvicorn", "securemailscope.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
