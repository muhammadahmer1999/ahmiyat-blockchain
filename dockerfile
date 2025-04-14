FROM ubuntu:22.04

RUN apt update && apt install -y g++ libssl-dev libleveldb-dev libcurl4-openssl-dev python3 python3-pip
RUN pip install flask flask-limiter

COPY src /app/src
COPY tests /app/tests
COPY api.py /app
COPY certs /app/certs
WORKDIR /app

RUN g++ -o ahmiyat src/*.cpp -lssl -lcrypto -pthread -lleveldb -lcurl -O2

CMD ["bash", "-c", "python3 api.py & ./ahmiyat 5001"]
