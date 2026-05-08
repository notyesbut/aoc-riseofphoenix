# Certs

Local-only self-signed certificates for the auth/launcher TLS endpoints.

## Why these aren't committed

The private keys (`ca.key`, `server.key`) and any cert files derived from
them are intentionally **gitignored**. Each contributor generates their
own pair. The certs are used solely for the loopback auth server — they
have no security meaning beyond "make the AoC client's HTTPS calls
succeed against `localhost`".

## Regenerate (Windows / PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File certs/regenerate.ps1
```

That's it. Outputs `ca.crt`, `ca.key`, `server.crt`, `server.key`, and a
combined `server.pem`, all confined to this folder.

## Regenerate manually (cross-platform)

```bash
cd certs/

# Self-signed CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 730 -key ca.key -out ca.crt \
    -subj '/CN=AOC-Emu Root CA/O=AoC Server Emulator'

# Server cert signed by the CA, with SANs from server_ext.cnf
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server_ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 730 -sha256 \
    -extensions v3_ext -extfile server_ext.cnf

cat server.crt server.key > server.pem
rm server.csr ca.srl
```

## Files in this folder (committed vs not)

| File | Tracked? | Purpose |
|---|---|---|
| `regenerate.ps1` | ✅ committed | Helper script to (re)generate the keys / certs |
| `server_ext.cnf` | ✅ committed | OpenSSL config (subject + SANs for the server cert) |
| `amazon_ca_bundle.pem` | ✅ committed | Mozilla CA bundle, used to validate AWS endpoints during MITM |
| `windows_roots.pem` | ✅ committed | Windows root CA list, used during cert chain analysis |
| `full_chain_raw.txt` | ✅ committed | Captured chain from MITM analysis (notes only, no keys) |
| `intrepid_chain.txt` | ✅ committed | Captured chain from MITM analysis (notes only, no keys) |
| `ca.key` | ❌ gitignored | CA private key — generate locally |
| `ca.crt` | ❌ gitignored | CA cert (regenerable) |
| `server.key` | ❌ gitignored | Server private key — generate locally |
| `server.crt` | ❌ gitignored | Server cert (regenerable) |
| `server.pem` | ❌ gitignored | Bundled cert + key (regenerable) |
