FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including Tesseract
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY privacylens/ ./privacylens/
COPY config.yaml ./

RUN pip install --no-cache-dir -e . \
    && python -m spacy download en_core_web_sm

EXPOSE 8000

CMD ["uvicorn", "privacylens.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

