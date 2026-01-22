FROM python:3.9-slim

# Install poppler-utils (Critical for converting Scanned PDFs to Images)
RUN apt-get update && apt-get install -y \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD ["sh", "-c", "python init_db.py && gunicorn -w 1 -b 0.0.0.0:10000 run:app"]