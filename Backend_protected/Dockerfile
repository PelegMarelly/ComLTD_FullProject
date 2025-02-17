# Base image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt ./ 
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . ./

# Explicitly copy the JSON file (to avoid issues with missing files)
COPY app/utils/init_packages_data.json /app/utils/init_packages_data.json

# Expose port 10000
EXPOSE 10000

# Command to run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "10000", "--reload"]
