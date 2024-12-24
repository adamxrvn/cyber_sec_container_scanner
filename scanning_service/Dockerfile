# scanning_service/Dockerfile

FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# If you run Docker in Docker or do container exec calls, you might need:
# RUN apt-get update && apt-get install -y docker.io
# (Only if your scanning logic actually calls `docker exec` on the same machine.)
# But typically your scanning container just needs the code plus `docker.from_env()` logic,
# as long as the host provides access to Docker socket.

EXPOSE 81

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "81"]
