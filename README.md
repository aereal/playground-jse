Generate keys:

```sh
make keys
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
