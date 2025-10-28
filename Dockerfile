FROM python:3.12-trixie

RUN apt-get update && apt-get install -y --no-install-recommends gcc libldap2-dev libsasl2-dev libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8000
ENV PORT=8000
ENV BIND=0.0.0.0

CMD ["python", "server.py"]
