# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code into the container at /app
COPY . .

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define environment variable for the secret key.
# It's recommended to override this at runtime.
ENV SECRET_KEY="a_default_secret_key_that_should_be_overridden"

# Run the application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]