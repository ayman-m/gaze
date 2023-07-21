# Use an official Python runtime as the base image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /


# Copy the requirements.txt file into the container
COPY requirements.txt .

RUN apt-get update && apt-get install git -y
RUN pip3 install -r requirements.txt
RUN apt-get install -y ffmpeg

# Copy the /app and /data directories into the container
COPY ./app /app
COPY ./data /data
COPY ./models /models

# Copy the bot script into the container
COPY main.py .

# Run the bot script when the container launches
CMD ["python", "main.py"]
