# Shows the full TLS certificate chain sent by the server.
# 0 = leaf cert, 1 = intermediate, 2 = root (if provided).
# Use Ctrl + C to exit, or </dev/null to make it auto-close:
openssl s_client -connect your.domain.com:443 -showcerts

# Verify a certificate file
# Verifies the .cer file against local trusted roots and intermediates.
# Use this for standalone certs not necessarily installed yet.
certutil -verify client.cer

# List all certificates in a store
certutil -store My