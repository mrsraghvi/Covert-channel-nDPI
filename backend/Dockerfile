FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY backend/alembic.ini ./alembic.ini
COPY backend/migrations ./migrations
COPY detection ./detection
ENV PYTHONPATH=/app/detection

# Run as an unprivileged user — the container never needs root (no raw
# sockets / packet capture happens here, only the C engine on the host
# needs CAP_NET_RAW, and that runs outside Docker per docker-compose.yml).
RUN groupadd --system covertscope && useradd --system --gid covertscope --no-create-home covertscope \
    && mkdir -p /var/lib/covertscope \
    && chown -R covertscope:covertscope /app /var/lib/covertscope
USER covertscope

EXPOSE 8000 9999
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
