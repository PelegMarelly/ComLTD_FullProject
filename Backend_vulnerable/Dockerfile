# Use the official Python image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy the application code to the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the application port
EXPOSE 11000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "11000", "--reload"]
