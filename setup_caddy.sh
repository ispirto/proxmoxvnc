#!/bin/bash

# Setup script for Caddy server with Let's Encrypt certificates
# This script configures Caddy to reverse proxy to multiple services with HTTPS:
#   - Terminal routes (/terminal*, /ws*, /shell*) -> port 9000 (pxiarouter)
#   - VNC console (default) -> port 9999

set -e

DOMAIN="dalconsole.vpsdime.com"
EMAIL="info@vpsdime.com"
TERMINAL_PORT="9000"  # pxiarouter terminal service
VNC_PORT="9999"       # VNC console service

echo "==================================="
echo "Caddy + Let's Encrypt Setup Script"
echo "==================================="
echo "Domain: $DOMAIN"
echo "Email: $EMAIL"
echo "Terminal routes proxying to: localhost:$TERMINAL_PORT"
echo "VNC console proxying to: localhost:$VNC_PORT"
echo ""

# Step 1: Install Caddy
echo "[1/6] Installing Caddy..."
sudo apt update
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy

# Step 2: Install Certbot and ACL tools for Let's Encrypt
echo "[2/6] Installing Certbot and ACL tools..."
sudo apt install -y certbot acl

# Step 3: Stop Caddy temporarily to get certificates
echo "[3/6] Stopping Caddy to obtain certificates..."
sudo systemctl stop caddy

# Step 4: Get Let's Encrypt certificates using standalone mode
echo "[4/6] Obtaining Let's Encrypt certificates..."
sudo certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    --domains "$DOMAIN" \
    --keep-until-expiring

# Step 5: Create Caddy configuration
echo "[5/6] Creating Caddy configuration..."
sudo tee /etc/caddy/Caddyfile > /dev/null <<EOF
# Global options
{
    email $EMAIL
}

# HTTP redirect to HTTPS
http://$DOMAIN {
    redir https://$DOMAIN{uri} permanent
}

# HTTPS configuration with custom certificates
https://$DOMAIN {
    # Use Let's Encrypt certificates obtained via certbot
    tls /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/letsencrypt/live/$DOMAIN/privkey.pem

    # Terminal routes (pxiarouter)
    handle /terminal* {
        reverse_proxy localhost:$TERMINAL_PORT {
            header_up X-Forwarded-Host {host}
            header_up X-Forwarded-Proto {scheme}
            header_up X-Real-IP {remote}
        }
    }

    handle /ws* {
        reverse_proxy localhost:$TERMINAL_PORT {
            header_up X-Forwarded-Host {host}
            header_up X-Forwarded-Proto {scheme}
            header_up X-Real-IP {remote}
        }
    }

    handle /shell* {
        reverse_proxy localhost:$TERMINAL_PORT {
            header_up X-Forwarded-Host {host}
            header_up X-Forwarded-Proto {scheme}
            header_up X-Real-IP {remote}
        }
    }

    # VNC console (existing)
    handle {
        reverse_proxy localhost:$VNC_PORT {
            header_up Host {host}
            header_up X-Real-IP {remote}
            header_up X-Forwarded-For {remote}
            header_up X-Forwarded-Proto {scheme}

            # WebSocket support for VNC
            header_up Connection {>Connection}
            header_up Upgrade {>Upgrade}
        }
    }

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    # Logging
    log {
        output file /var/log/caddy/access.log
        format console
    }
}
EOF

# Step 6: Create log directory and set permissions
echo "[6/6] Setting up logging and permissions..."
sudo mkdir -p /var/log/caddy
sudo chown caddy:caddy /var/log/caddy

# Give caddy user permission to read Let's Encrypt certificates
sudo setfacl -R -m u:caddy:rx /etc/letsencrypt/live/
sudo setfacl -R -m u:caddy:rx /etc/letsencrypt/archive/

# Start and enable Caddy
echo "Starting Caddy service..."
sudo systemctl start caddy
sudo systemctl enable caddy

# Set up automatic certificate renewal
echo "Setting up automatic certificate renewal..."
sudo tee /etc/systemd/system/certbot-renewal.service > /dev/null <<EOF
[Unit]
Description=Certbot Renewal
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --pre-hook "systemctl stop caddy" --post-hook "systemctl start caddy"
EOF

sudo tee /etc/systemd/system/certbot-renewal.timer > /dev/null <<EOF
[Unit]
Description=Run certbot renewal twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable certbot-renewal.timer
sudo systemctl start certbot-renewal.timer

# Verify configuration
echo ""
echo "==================================="
echo "Setup Complete!"
echo "==================================="
echo ""
echo "Checking Caddy status..."
sudo systemctl status caddy --no-pager | head -n 10

echo ""
echo "Checking certificate status..."
sudo certbot certificates

echo ""
echo "Configuration summary:"
echo "  - Domain: https://$DOMAIN"
echo "  - Terminal routes (/terminal*, /ws*, /shell*): localhost:$TERMINAL_PORT"
echo "  - VNC console (default): localhost:$VNC_PORT"
echo "  - Certificates: /etc/letsencrypt/live/$DOMAIN/"
echo "  - Caddy config: /etc/caddy/Caddyfile"
echo "  - Access logs: /var/log/caddy/access.log"
echo ""
echo "Note: Make sure your applications are running on:"
echo "      - Port $TERMINAL_PORT (pxiarouter terminal service)"
echo "      - Port $VNC_PORT (VNC console service)"
echo "Note: DNS for $DOMAIN must point to this server's IP"