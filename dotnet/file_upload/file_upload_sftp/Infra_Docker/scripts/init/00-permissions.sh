#!/bin/sh
set -e

# Ensure outbound folders exist
mkdir -p /home/uploader/outbound
mkdir -p /home/partnerA/outbound
mkdir -p /home/partnerB/outbound

# Create "views" for uploader: outbound/partnerA -> /home/partnerA/outbound
# Use symlinks to avoid extra mounts
ln -sf /home/partnerA/outbound /home/uploader/outbound/partnerA
ln -sf /home/partnerB/outbound /home/uploader/outbound/partnerB

# Permission model (simple dev version):
# Partners own their outbound so they can delete after download.
chown -R 1002:1002 /home/partnerA/outbound
chown -R 1003:1003 /home/partnerB/outbound

# Allow uploader to write into those folders (dev-friendly).
# In real life you'd use groups or ACLs instead of chmod 775.
chmod -R 775 /home/partnerA/outbound /home/partnerB/outbound