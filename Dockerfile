FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifest
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose ports for Streamlit (8501) and FastAPI (8000)
EXPOSE 8501 8000

# Default command: launch Streamlit Dashboard
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
