# Use an official Python runtime as the base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# System deps some Python packages (e.g. selenium/cryptography) may need
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first so Docker can cache the pip install layer
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app code (main.py, admin.py, dashboard.py, templates, etc.)
COPY app/ .

# Copy the ROADtools submodule if it's not installed via pip
COPY ROADtools/ /ROADtools/
RUN pip install --no-cache-dir -e /ROADtools/ || true

ENV FLASK_APP=main.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "main.py"]