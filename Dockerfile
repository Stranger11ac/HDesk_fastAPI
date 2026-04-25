FROM python:3.11-slim
WORKDIR /app

# Copia primero dependencias (cache)
COPY main.txt .
RUN pip install --no-cache-dir -r main.txt

# Luego el código
COPY . .
