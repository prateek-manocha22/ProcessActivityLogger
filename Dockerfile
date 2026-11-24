FROM python:3.12-slim

# ps, top, kill, pstree for testing our logger
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps psmisc git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["sleep", "infinity"]
