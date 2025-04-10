# Use the official Python 3.13.2 slim base image
FROM python:3.13.2-slim

# Set the working directory to /app
WORKDIR /app

# Copy the project files into the container
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV TORBOX_API_BASE="https://api.torbox.app"
ENV TORBOX_API_VERSION="v1"
ENV WATCH_DIR="/app/watch"
ENV DOWNLOAD_DIR="/app/downloads"
ENV WATCH_INTERVAL="60"
ENV CHECK_INTERVAL="300"
ENV MAX_RETRIES="2"
ENV ALLOW_ZIP="true"
ENV SEED_PREFERENCE="1"
ENV POST_PROCESSING="-1"
ENV QUEUE_IMMEDIATELY="false"
ENV PROGRESS_INTERVAL="15"
ENV WEB_PORT="5151"

# The TORBOX_API_KEY is intentionally left unset here.
# It must be provided by the user when running the container.

# Set the entry point
CMD ["python", "main.py"]
