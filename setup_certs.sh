#!/bin/bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem -out certs/cert.pem -days 365 -subj "/C=US/ST=CA/O=Ahmiyat"
echo "TLS certificates generated in certs/"
