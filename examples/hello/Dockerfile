# syntax=docker/dockerfile:1
# Base image pinned by digest. Swapping it for a hardened base (docs/security.md) is a one-line change.
ARG BASE=docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
FROM ${BASE}
WORKDIR /app
COPY app.py .
ARG APP_COMMIT=unknown
ENV APP_COMMIT=${APP_COMMIT} PYTHONUNBUFFERED=1 PORT=8080
USER 65532:65532
EXPOSE 8080
HEALTHCHECK NONE
CMD ["python3", "/app/app.py"]
