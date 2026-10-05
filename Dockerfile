FROM python:3.12-alpine

WORKDIR /app

COPY server.py .
COPY static ./static
COPY data ./data

EXPOSE 8080

CMD ["python", "server.py"]
