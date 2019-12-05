OPENSSL = /usr/local/opt/openssl@1.1/bin/openssl
KEYS_DIR = ./keys
PRIVATE_KEY = $(KEYS_DIR)/private.pem
PUBLIC_KEY = $(KEYS_DIR)/public.pem

.PHONY: keys
keys: $(PRIVATE_KEY) $(PUBLIC_KEY)

.PHONY: clean
clean:
	rm -f $(PUBLIC_KEY) $(PRIVATE_KEY)

$(PRIVATE_KEY):
	$(OPENSSL) genrsa -out $(PRIVATE_KEY) 4096

$(PUBLIC_KEY): $(PRIVATE_KEY)
	$(OPENSSL) rsa -in $(PRIVATE_KEY) -pubout -out $(PUBLIC_KEY)
