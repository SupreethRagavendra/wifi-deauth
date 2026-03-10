FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port
EXPOSE 5000

# Run the application
CMD ["uvicorn", "ml_service:app", "--host", "0.0.0.0", "--port", "5000"]
