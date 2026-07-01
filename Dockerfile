FROM python:3.14-slim

WORKDIR /app

RUN groupadd -r sdg && useradd -r -g sdg sdg

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sdg/ ./sdg/

USER sdg

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

CMD ["python3", "-m", "uvicorn", "sdg.frontend.app:app", "--host", "0.0.0.0", "--port", "8000"]
