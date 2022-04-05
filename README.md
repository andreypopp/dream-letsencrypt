# dream-letsencrypt with TLS-ALPN-01

This is an example [Dream][] app demonstrating integration with [LetsEncrypt]
using [TLS-ALPN-01] challenge.

How to run it:

- Run `make init` to initialize a local opam switch and install needed
  dependencies.

- Make sure your machine is exposed to the internet on port 443 (HTTPS) and has
  a domain name pointing to it (this is needed to actually issue a certificate
  for).

- Run `make start` which will
  - Generate a new private key for the CA account
  - Generate a new private key for the web server
  - Generate a new certificate signing request (using the web server private
    key) for your domain (you need to enter it once openssl asks about "Common
    name (e.g FQDN)").
  - Start a web server which will check for a certificate to be present and if
    not will:
    - Ensure the account with CA is created
    - Will create new order based on CSR for a new certificate
    - Use TLS-ALPN-01 challenge for CA to be sure we have control over the
      domain.
    - Download issues certificates and save them on disk (for further restarts
      to use them directly)
    - Start the actual Dream app using issued certificate.

Some notes:

- See `dune exec -- example/main.exe --help` for options, but for now it just
  lists the options for locations of CSR/account key/web server key which are
  generated by `Makefile`

- For TLS-ALPN-01 challenge another Dream app is used. The Dream codebase was
  forked to add support for `acme-tls/1` ALPN. The app does nothing if
  `acme-tls/1` is negotiated and just closes the socket after negotiation is
  done.

  Ideally Dream codebase is enhanced to add support for:

  - Dynamically configured certificate so we can accept new connections using
    new certificate without server restart.

  - Support for using different certificates/keys for different ALPNs, so
    solving challenges can be done in parallel with serving user requests.

[Dream]: https://aantron.github.io/dream/
[LetsEncrypt]: https://letsencrypt.org/
[TLS-ALPN-01]: https://datatracker.ietf.org/doc/html/rfc8737
