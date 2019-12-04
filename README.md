Generate keys:

```sh
/usr/local/opt/openssl/bin/openssl genrsa -out ./keys/private-key.pem 4096
/usr/local/opt/openssl/bin/openssl rsa -in ./keys/private-key.pem -pubout -out ./keys/public-key.pem
```

Run issuer who creates the token:

```
# cpm install
carton exec -- perl issuer.pl
```

Run consumer who decrypt/verify the token:

```
# yarn
carton exec -- perl issuer.pl | node consumer.js
```

You may get the result such as:

```
✘╹◡╹✘ < carton exec -- perl ./issuer.pl | node ./consumer.js
{"uid":123}
```
