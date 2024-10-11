.PHONY: cert
cert: snakeoil.crt

snakeoil.crt:
	openssl req -newkey rsa:2048 -keyout snakeoil.key -noenc -subj "/C=IE/CN=localhost/O=Turscar" -x509 -days 365 -out snakeoil.crt