FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for qrcode and other libraries
RUN apt-get update && apt-get install -y \
    libz-dev \
    libjpeg-dev \
    libfreetype6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure we can find the app in the python path
ENV PYTHONPATH=/app

EXPOSE 8000

# Start uvicorn. 
# Note: we use --host 0.0.0.0 to listen on all interfaces within the container.
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
