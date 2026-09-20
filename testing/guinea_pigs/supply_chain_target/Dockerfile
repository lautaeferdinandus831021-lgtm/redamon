# WhiteHat Supply-Chain recon (L2) guinea pig.
# Pure stdlib Python: no pip install, no deps to drift, ~55 MB, boots in ~1s.
FROM python:3.11-alpine

WORKDIR /app
COPY server.py /app/server.py

ENV PYTHONUNBUFFERED=1 \
    SC_TARGET_PORT=80

EXPOSE 80
CMD ["python3", "/app/server.py"]
