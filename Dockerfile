# 1. Use a lightweight Python base image
FROM python:3.9-slim

# 2. Install System Dependencies (Crucial for OCR & PDF)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    poppler-utils \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 3. Set work directory
WORKDIR /app

# 4. Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy the rest of the app code
COPY . .

# 6. Command to run the app using Gunicorn (Production Server)
# format: gunicorn -w 4 -b 0.0.0.0:PORT run:app
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:10000", "run:app"]