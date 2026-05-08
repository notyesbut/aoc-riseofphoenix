# ============================================================================
#  certs/regenerate.ps1
#
#  Generate a fresh self-signed CA + server cert pair for local development.
#  These certs are NOT committed to the repo — every contributor generates
#  their own. They're only used for the local loopback auth server.
#
#  Run from the repo root:
#      powershell -ExecutionPolicy Bypass -File certs/regenerate.ps1
#
#  Output:
#      certs/ca.key       (CA private key — gitignored)
#      certs/ca.crt       (self-signed CA cert)
#      certs/server.key   (server private key — gitignored)
#      certs/server.crt   (CA-signed server cert)
#      certs/server.pem   (server.crt + server.key bundle)
#
#  Requires: OpenSSL on PATH (Git for Windows ships one).
# ============================================================================

$ErrorActionPreference = 'Stop'
$CertsDir = $PSScriptRoot
Push-Location $CertsDir

try {
    Write-Host "Removing old keys / certs (if any) ..."
    Remove-Item server.crt, server.key, server.pem, ca.key, ca.crt, server.csr, ca.srl -ErrorAction SilentlyContinue

    Write-Host "Generating CA private key + self-signed CA cert ..."
    & openssl genrsa -out ca.key 2048 2>&1 | Out-Null
    & openssl req -new -x509 -days 730 -key ca.key -out ca.crt `
        -subj '/CN=AOC-Emu Root CA/O=AoC Server Emulator' 2>&1 | Out-Null

    Write-Host "Generating server private key + CSR ..."
    & openssl genrsa -out server.key 2048 2>&1 | Out-Null
    & openssl req -new -key server.key -out server.csr -config server_ext.cnf 2>&1 | Out-Null

    Write-Host "Signing server cert with the CA ..."
    & openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial `
        -out server.crt -days 730 -sha256 `
        -extensions v3_ext -extfile server_ext.cnf 2>&1 | Out-Null

    Write-Host "Bundling server.pem (cert + key) ..."
    Get-Content server.crt, server.key | Set-Content -Encoding ASCII server.pem

    Write-Host "Cleaning up CSR + serial ..."
    Remove-Item server.csr, ca.srl -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Verifying chain:" -ForegroundColor Cyan
    & openssl verify -CAfile ca.crt server.crt
    Write-Host ""
    Write-Host "Generated cert subjects:" -ForegroundColor Cyan
    & openssl x509 -in ca.crt -noout -subject
    & openssl x509 -in server.crt -noout -subject -ext subjectAltName

    Write-Host ""
    Write-Host "Done. Certs are in $CertsDir" -ForegroundColor Green
}
finally {
    Pop-Location
}
