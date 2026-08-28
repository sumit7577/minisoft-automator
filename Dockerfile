# Use an official Python runtime as the base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# System deps some Python packages (e.g. selenium/cryptography) may need
# firefox-esr is the actual browser Selenium drives; geckodriver itself is
# fetched automatically at runtime by Selenium 4's Selenium Manager.
# xvfb + xauth provide a virtual display so Firefox can run non-headless
# (HEADLESS = False in main.py) on a display-less server.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    git \
    firefox-esr \
    xvfb \
    xauth \
    wget \
    && GECKO=$(wget -qO- https://api.github.com/repos/mozilla/geckodriver/releases/latest \
       | grep '"tag_name"' | cut -d'"' -f4) \
    && wget -qO /tmp/gecko.tar.gz \
       "https://github.com/mozilla/geckodriver/releases/download/${GECKO}/geckodriver-${GECKO}-linux64.tar.gz" \
    && tar -xzf /tmp/gecko.tar.gz -C /usr/local/bin \
    && rm /tmp/gecko.tar.gz \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first so Docker can cache the pip install layer
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app code (main.py, admin.py, dashboard.py, templates, etc.)
COPY app/ .

# Install roadtx from upstream. Keep this as a RUN layer: installing it by hand in a
# running container and `docker commit`-ing the result overwrites the image CMD with
# the pip command, which silently replaces the entrypoint and breaks the container.
RUN pip install --no-cache-dir git+https://github.com/dirkjanm/ROADtools.git#subdirectory=roadtx

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLASK_APP=main.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["/entrypoint.sh"]