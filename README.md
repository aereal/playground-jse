```sh
/usr/local/opt/openssl/bin/openssl genrsa -out ./keys/private-key.pem 4096
/usr/local/opt/openssl/bin/openssl rsa -in ./keys/private-key.pem -pubout -out ./keys/public-key.pem
```
