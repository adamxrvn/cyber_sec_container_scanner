# vulnerabilities_management/Dockerfile

FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port 7000 if that's what your main.py uses by default
EXPOSE 82

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "82"]
