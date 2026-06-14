# Κοινό image για όλες τις υπηρεσίες του application-level SDN
FROM python:3.12-slim

WORKDIR /app

# εξαρτήσεις
COPY app_sdn/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# κώδικας: χρειαζόμαστε ml_pipeline (config, detection_engine), controller, models
COPY ml_pipeline /app/ml_pipeline
COPY controller /app/controller
COPY app_sdn /app/app_sdn
COPY models /app/models

# προεπιλογή: τίποτα (το ορίζει το docker-compose ανά υπηρεσία)
CMD ["python3", "app_sdn/controller.py"]
