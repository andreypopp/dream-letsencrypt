build:
	dune build -p dream-pure,dream-httpaf,dream,dream-letsencrypt,hyper --no-print-directory @install

init:
	git submodule init
	git submodule update --recursive
	opam switch create . 4.12.1 -y
	opam install --deps-only -y --with-test \
		./dream/dream.opam \
		./dream/dream-httpaf.opam \
		./dream/dream-pure.opam \
		./hyper/hyper.opam 
	opam install -y letsencrypt
	opam install -y 'caqti<1.8.0'
	opam install -y 'mirage-stack<4'

account.pem:
	openssl genrsa > $@

csr.pem privkey.pem:
	openssl req -nodes -newkey rsa > $@

start: account.pem csr.pem
	dune exec -- \
		./example/main.exe \
		--account account.pem \
		--csr csr.pem \
		--key privkey.pem

clean:
	*.pem
