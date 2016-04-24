# Acme/PKI

Tiny PKI based on [Acme/client](https://github.com/unixcharles/acme-client).

Licensed under [AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html).

## Usage
### Generate secret key

	Usage: letsencrypt key <domain> [options]
		-r, --rsa [KEYSIZE]              RSA key, key size
		-e, --ecc [CURVE]                ECC key, curve

Generate a key (default is an EC secp384r1 key) in `example.bar.foo.pem`

	letsencrypt key foo.bar.example

Default key is an EC secp384r1.

### Generate certificate request

	Usage: letsencrypt csr <domain> [options]
		-k, --key [KEYFILE]              Key file
		-d, --domains [DOMAINS]          Domains

Generate a certificate request in `example.bar.foo.csr`

	letsencrypt csr foo.bar.example

### Request certificate

	Usage: letsencrypt crt <domain> [options]
		-c, --csr [CSR]                  CSR file

Request the corresponding certificate in `example.bar.foo.crt`

	letsencrypt crt foo.bar.example

You can call directly the certificate issuance, CSR and key will be created when needed.

### Renew certificate

	Usage: letsencrypt renew <domain> [options]
		-c, --csr [CSR]                  CSR file

Renew the `example.bar.foo.crt` if needed (default is 30d before expiration).

	letsencrypt renew foo.bar.example

If certificate was renewed, return code is 1 else 0, for post-action on crontab for example

	#!/bin/bash
	cd /etc/ssl/private
	
	if letsencrypt renew foo.bar.example; then
		service apache2 reload
	fi

### Get information from key or certificate

	letsencrypt info <domain> [options]
		-k, --key                        Key information
		-c, --crt                        Certificate information

Display various information (fingerprints, HPKP, TLSA…) for key or certificate.

	letsencrypt info foo.bar.example
	letsencrypt info -c foo.bar.example

## Environment variables

You can define which ACME endpoint is used with `ACME_ENDPOINT` environment variable.
Default is Let’s encrypt production endpoint (`https://acme-v01.api.letsencrypt.org/`).
You can use Let’s encrypt staging endpoint (`https://acme-staging.api.letsencrypt.org/`) for testing.

Default account key is `account.key` in the current directory. You can specify another key file with `ACME_ACCOUNT_KEY` environment variable.

Default ACME challenge directory is `acme-challenge` in the current directory.
You can change it with `ACME_CHALLENGE` environment variable.
