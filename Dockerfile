FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY kavach ./kavach
COPY frontend ./frontend

# Run as a non-root user; keep the database in a mounted volume
RUN useradd --create-home kavach && mkdir /data && chown kavach /data
USER kavach
ENV KAVACH_DB_PATH=/data/kavach.db

EXPOSE 8000
# One worker on purpose: the rate limiter and cache are in memory
CMD ["uvicorn", "kavach.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--workers", "1"]
