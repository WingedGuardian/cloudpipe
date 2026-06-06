"""Minimal service--the infrastructure pipeline is the project, not this."""
import os

from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok", "environment": os.getenv("ENVIRONMENT", "unknown")}


@app.get("/")
def root():
    return {"service": "cloudpipe", "version": "0.1.0"}
