FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY flareproxy.py .

EXPOSE 8080 8443

CMD ["python", "flareproxy.py"]
