# 1. Use a lightweight Python base image
FROM python:3.9-slim

# 2. Install System Dependencies (Crucial for OCR & PDF handling)
# We install tesseract-ocr (for reading images) and libpq-dev (for database)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    poppler-utils \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 3. Set work directory inside the container
WORKDIR /app

# 4. Copy requirements and install Python dependencies first (for caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy the rest of the application code
COPY . .

# 6. Command to run the app
# CRITICAL FIX: We use "sh -c" to run two commands in order:
# 1. "python init_db.py" -> Creates the tables safely (single process)
# 2. "gunicorn ..." -> Starts the web server (multiple workers)
CMD ["sh", "-c", "python init_db.py && gunicorn -w 4 -b 0.0.0.0:10000 run:app"]