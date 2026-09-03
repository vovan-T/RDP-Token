# Required public trust material

Place your client-issuing CA certificate(s) in `client-ca.pem` and its current
PEM-encoded CRL in `client.crl.pem`. These are public trust files, not private keys.
Both must be readable by container UID 10001. A missing or expired CRL denies
certificate login. Keep the CRL current using your CA's publication procedure;
this source package does not install an automatic CRL downloader.

The HTTPS server full chain and private key are configured separately in `.env`
and mounted read-only into nginx. Do not put your CA signing private key on the
gateway. Do not commit deployment certificates or keys to Git.

Start with a dedicated test root CA and directly issued client certificates.
More complex intermediate-CA deployments require separate chain/CRL testing.
