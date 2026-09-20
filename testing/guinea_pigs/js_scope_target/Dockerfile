# WhiteHat JS recon scope guinea pig. Pure stdlib, no dependencies.
FROM python:3.11-alpine

WORKDIR /app
COPY server.py /app/server.py
COPY static /app/static

ENV PYTHONUNBUFFERED=1

EXPOSE 80 8080
CMD ["python3", "/app/server.py"]
