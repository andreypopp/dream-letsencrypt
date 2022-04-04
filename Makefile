build:
	dune build -p dream-pure,dream-httpaf,dream,dream-letsencrypt,hyper --no-print-directory @install

account.pem:
	openssl genrsa > $@

csr.pem:
	openssl req -nodes -newkey rsa > $@

start:
	dune exec ./example/main.exe

clean:
	*.pem
