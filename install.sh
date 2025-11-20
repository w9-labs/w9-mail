#!/usr/bin/env bash

set -euo pipefail

# Line-buffered output
exec 1> >(stdbuf -oL cat)
exec 2> >(stdbuf -oL cat >&2)

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Config
SERVICE_NAME=w9-mail
INSTALL_DIR=/opt/w9-mail
SERVICE_USER=w9-mail
DATA_DIR=$INSTALL_DIR/data
APP_PORT=${APP_PORT:-8080}
DOMAIN=${DOMAIN:-w9.nu}
BASE_URL=${BASE_URL:-https://$DOMAIN}
FRONTEND_PUBLIC=/var/www/w9-mail

# Backup for rollback
BACKUP_DIR=/tmp/w9-mail_backup_$$
NEED_ROLLBACK=false

cleanup() {
    if [ "$NEED_ROLLBACK" = "true" ]; then
        echo "ERROR: Deployment failed, rolling back..."
        if [ -f "$BACKUP_DIR/w9-mail-backend" ]; then
            $SUDO_CMD cp "$BACKUP_DIR/w9-mail-backend" "$INSTALL_DIR/w9-mail-backend" 2>/dev/null || true
        fi
        if [ -d "$BACKUP_DIR/frontend" ]; then
            $SUDO_CMD rm -rf "$FRONTEND_PUBLIC"
            $SUDO_CMD cp -r "$BACKUP_DIR/frontend" "$FRONTEND_PUBLIC" 2>/dev/null || true
        fi
        $SUDO_CMD systemctl start $SERVICE_NAME 2>/dev/null || true
        echo "Rollback attempted"
    fi
    rm -rf "$BACKUP_DIR" 2>/dev/null || true
}

trap cleanup EXIT

# Detect if running as root
if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=true
    SUDO_CMD=""
else
    IS_ROOT=false
    SUDO_CMD="sudo"
    # Check if user has sudo privileges
    if ! sudo -n true 2>/dev/null; then
        echo "This script requires sudo privileges or to be run as root"
        exit 1
    fi
fi

# Build user
if [ "$IS_ROOT" = "true" ]; then
    # If running as root, try to find the actual owner of the directory
    BUILD_USER=$(stat -c '%U' "$ROOT_DIR" 2>/dev/null || echo "root")
    # If directory is owned by root, try to find a non-root user with home directory
    if [ "$BUILD_USER" = "root" ]; then
        # Try to find first non-root user
        BUILD_USER=$(getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {print $1; exit}' || echo "root")
    fi
else
    BUILD_USER="${SUDO_USER:-$(whoami)}"
fi

# Install packages (only if needed)
echo "Checking packages..."
REQUIRED_PKGS="build-essential pkg-config libsqlite3-dev sqlite3 nodejs npm nginx ufw openssl libssl-dev"
MISSING_PKGS=""
for pkg in $REQUIRED_PKGS; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done
if [ -n "$MISSING_PKGS" ]; then
    echo "Installing missing packages:$MISSING_PKGS"
    $SUDO_CMD apt-get update -qq >/dev/null 2>&1 || true
    $SUDO_CMD apt-get install -y $MISSING_PKGS >/dev/null 2>&1 || true
fi
echo "✓ Packages ready"

# Install Rust if needed
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    # Always install Rust for root when running as root
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || {
        echo "Failed to install Rust"
        exit 1
    }
    # Source cargo env for current shell
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

# Create service user
id -u $SERVICE_USER >/dev/null 2>&1 || $SUDO_CMD useradd --system --create-home --home-dir $INSTALL_DIR --shell /usr/sbin/nologin $SERVICE_USER

# Check if rebuild is needed
BACKEND_NEEDS_BUILD=true
FRONTEND_NEEDS_BUILD=true

if [ -f "$ROOT_DIR/backend/target/release/w9-mail-backend" ]; then
    BINARY_TIME=$(stat -c %Y "$ROOT_DIR/backend/target/release/w9-mail-backend" 2>/dev/null || echo 0)
    NEWEST_SRC=$(find "$ROOT_DIR/backend/src" "$ROOT_DIR/backend/Cargo.toml" -type f \( -name "*.rs" -o -name "Cargo.toml" \) 2>/dev/null | xargs stat -c %Y 2>/dev/null | sort -n | tail -1 || echo 0)
    [ "$NEWEST_SRC" -lt "$BINARY_TIME" ] && [ "$NEWEST_SRC" -gt 0 ] && BACKEND_NEEDS_BUILD=false
fi

if [ -d "$ROOT_DIR/frontend/out" ]; then
    DIST_TIME=$(stat -c %Y "$ROOT_DIR/frontend/out" 2>/dev/null || echo 0)
    NEWEST_FE=$(find "$ROOT_DIR/frontend/app" "$ROOT_DIR/frontend/public" "$ROOT_DIR/frontend/package.json" "$ROOT_DIR/frontend/next.config.js" -type f 2>/dev/null | xargs stat -c %Y 2>/dev/null | sort -n | tail -1 || echo 0)
    [ "$NEWEST_FE" -lt "$DIST_TIME" ] && [ "$NEWEST_FE" -gt 0 ] && FRONTEND_NEEDS_BUILD=false
fi

# Build backend (if needed)
if [ "$BACKEND_NEEDS_BUILD" = "true" ]; then
    echo "Building backend..."
    cd "$ROOT_DIR/backend"
    
    # Setup cargo environment
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    elif [ "$BUILD_USER" != "root" ] && [ -f "/home/$BUILD_USER/.cargo/env" ]; then
        export PATH="/home/$BUILD_USER/.cargo/bin:$PATH"
    fi
    
    # Build as current user (root or regular user)
    if [ "$IS_ROOT" = "true" ] && [ "$BUILD_USER" != "root" ] && id -u "$BUILD_USER" >/dev/null 2>&1; then
        # Running as root, but try to build as non-root user if they exist
        if [ -f "/home/$BUILD_USER/.cargo/env" ]; then
            sudo -u $BUILD_USER bash -c "cd '$ROOT_DIR/backend' && source /home/$BUILD_USER/.cargo/env && cargo build --release" 2>&1 | tail -2
        else
            # Build as root if build user doesn't have cargo
            cargo build --release 2>&1 | tail -2
        fi
    else
        # Build as current user (root or regular)
        cargo build --release 2>&1 | tail -2
    fi
else
    echo "✓ Backend is up to date, skipping rebuild"
fi

# Build frontend (if needed)
if [ "$FRONTEND_NEEDS_BUILD" = "true" ]; then
    echo "Building frontend..."
    cd "$ROOT_DIR/frontend"
    # Use npm ci if package-lock.json exists and is in sync, otherwise use npm install
    if [ -f "package-lock.json" ]; then
        if npm ci --prefer-offline --no-audit 2>&1 | tail -1; then
            echo "✓ Dependencies installed with npm ci"
        else
            echo "⚠ package-lock.json out of sync, updating..."
            npm install --prefer-offline --no-audit 2>&1 | tail -1
        fi
    else
        npm install --prefer-offline --no-audit 2>&1 | tail -1
    fi
    npm run build 2>&1 | tail -1
else
    echo "✓ Frontend is up to date, skipping rebuild"
fi

# Stop service before deployment
echo "Stopping $SERVICE_NAME service..."
$SUDO_CMD systemctl stop $SERVICE_NAME 2>/dev/null || true
sleep 1

# Kill any processes using the port
$SUDO_CMD fuser -k $APP_PORT/tcp 2>/dev/null || true
sleep 1

# Verify port is free
if $SUDO_CMD ss -tulpn | grep -q ":$APP_PORT "; then
    echo "WARNING: Port $APP_PORT still in use, forcing cleanup..."
    $SUDO_CMD pkill -9 w9-mail-backend 2>/dev/null || true
    sleep 1
fi

# Enable rollback on failure from this point
NEED_ROLLBACK=true

# Backup existing installation
echo "Creating backup..."
mkdir -p "$BACKUP_DIR"
[ -f "$INSTALL_DIR/w9-mail-backend" ] && cp "$INSTALL_DIR/w9-mail-backend" "$BACKUP_DIR/w9-mail-backend" 2>/dev/null || true
[ -d "$FRONTEND_PUBLIC" ] && cp -r "$FRONTEND_PUBLIC" "$BACKUP_DIR/frontend" 2>/dev/null || true

# Install binary
echo "Installing binary..."
$SUDO_CMD mkdir -p $INSTALL_DIR $DATA_DIR
$SUDO_CMD cp "$ROOT_DIR/backend/target/release/w9-mail-backend" "$INSTALL_DIR/w9-mail-backend"
$SUDO_CMD chown root:$SERVICE_USER "$INSTALL_DIR/w9-mail-backend"
$SUDO_CMD chmod 750 "$INSTALL_DIR/w9-mail-backend"
$SUDO_CMD chown -R $SERVICE_USER:$SERVICE_USER $DATA_DIR
$SUDO_CMD chmod -R 755 $DATA_DIR

# Install frontend
echo "Installing frontend..."
$SUDO_CMD mkdir -p $FRONTEND_PUBLIC
$SUDO_CMD rm -rf $FRONTEND_PUBLIC/* 2>/dev/null || true

# Copy Next.js static export output
if [ -d "$ROOT_DIR/frontend/out" ]; then
    $SUDO_CMD cp -r "$ROOT_DIR/frontend/out"/* $FRONTEND_PUBLIC/
fi

$SUDO_CMD chown -R root:root $FRONTEND_PUBLIC

# Env file
$SUDO_CMD tee /etc/default/$SERVICE_NAME >/dev/null <<EOF
HOST=0.0.0.0
PORT=$APP_PORT
BASE_URL=$BASE_URL
DATABASE_PATH=$DATA_DIR/w9mail.db
EOF

# Systemd unit
$SUDO_CMD tee /etc/systemd/system/$SERVICE_NAME.service >/dev/null <<EOF
[Unit]
Description=W9 Mail - Email Service API
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/default/$SERVICE_NAME
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/w9-mail-backend
User=$SERVICE_USER
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# Nginx config (Cloudflare handles SSL, nginx just proxies)
echo "Configuring nginx..."
cat > /tmp/nginx_$SERVICE_NAME.conf << 'NGINX_EOF'
# HTTP server (redirect to HTTPS - Cloudflare will handle SSL)
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

# HTTPS server (Cloudflare terminates SSL, nginx receives HTTP from Cloudflare)
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;

    # SSL certificates (Cloudflare origin cert or self-signed for Cloudflare)
    ssl_certificate /etc/ssl/certs/cloudflare-origin.pem;
    ssl_certificate_key /etc/ssl/private/cloudflare-origin.key;
    
    # Fallback to self-signed if Cloudflare cert doesn't exist
    if (!-f /etc/ssl/certs/cloudflare-origin.pem) {
        ssl_certificate /etc/nginx/ssl/w9.nu/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/w9.nu/key.pem;
    }

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    client_max_body_size 100M;

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
    }

    # Health check
    location /health {
        proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER;
        proxy_set_header Host $host;
        access_log off;
    }

    # Frontend static files
    root FRONTEND_PUBLIC_PLACEHOLDER;
    index index.html;

    # Static assets with caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webmanifest|woff|woff2|ttf|eot)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    # Frontend routes (Next.js static export)
    location / {
        try_files $uri $uri/ $uri.html /index.html;
    }
}
NGINX_EOF

# Replace placeholders
sed -i "s|FRONTEND_PUBLIC_PLACEHOLDER|$FRONTEND_PUBLIC|g" /tmp/nginx_$SERVICE_NAME.conf
sed -i "s|APP_PORT_PLACEHOLDER|$APP_PORT|g" /tmp/nginx_$SERVICE_NAME.conf

# Generate self-signed cert for fallback (Cloudflare will use its own)
SSL_DIR="/etc/nginx/ssl/$DOMAIN"
$SUDO_CMD mkdir -p $SSL_DIR
if [ ! -f "$SSL_DIR/cert.pem" ]; then
    $SUDO_CMD openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_DIR/key.pem" \
        -out "$SSL_DIR/cert.pem" \
        -subj "/CN=$DOMAIN" 2>/dev/null
    $SUDO_CMD chmod 600 "$SSL_DIR/key.pem"
    $SUDO_CMD chmod 644 "$SSL_DIR/cert.pem"
    echo "✓ Self-signed certificate created (fallback)"
fi

# Install nginx config
$SUDO_CMD cp /tmp/nginx_$SERVICE_NAME.conf /etc/nginx/sites-available/$SERVICE_NAME
rm /tmp/nginx_$SERVICE_NAME.conf
$SUDO_CMD rm -f /etc/nginx/sites-enabled/default
$SUDO_CMD ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/$SERVICE_NAME

# Start services
echo "Starting services..."
$SUDO_CMD systemctl daemon-reload
$SUDO_CMD systemctl enable $SERVICE_NAME nginx 2>&1 | grep -v "Created symlink" || true

# Reload nginx config (faster than restart if already running)
if $SUDO_CMD systemctl is-active --quiet nginx; then
    $SUDO_CMD nginx -t && $SUDO_CMD systemctl reload nginx || $SUDO_CMD systemctl restart nginx
else
    $SUDO_CMD systemctl start nginx
fi

# Start w9-mail service
$SUDO_CMD systemctl start $SERVICE_NAME

# Enable firewall rules
$SUDO_CMD ufw allow 80/tcp 443/tcp 2>/dev/null || true

# Verify deployment
echo ""
echo "=== VERIFICATION ==="

# Wait for service to start with timeout
echo -n "Waiting for service to start"
for i in {1..15}; do
    sleep 1
    echo -n "."
    if $SUDO_CMD systemctl is-active --quiet $SERVICE_NAME; then
        break
    fi
    if [ $i -eq 15 ]; then
        echo ""
        echo "✗ Service failed to start"
        $SUDO_CMD journalctl -u $SERVICE_NAME --no-pager -n 20
        exit 1
    fi
done
echo ""

# Check services
for service in $SERVICE_NAME nginx; do
    if $SUDO_CMD systemctl is-active --quiet $service; then
        echo "✓ $service running"
    else
        echo "✗ $service FAILED"
        $SUDO_CMD journalctl -u $service --no-pager -n 10
        exit 1
    fi
done

# Check backend health with retries
echo -n "Checking backend health"
for i in {1..10}; do
    sleep 1
    echo -n "."
    if curl -sf http://127.0.0.1:$APP_PORT/health >/dev/null 2>&1; then
        echo ""
        echo "✓ Backend healthy"
        NEED_ROLLBACK=false
        break
    fi
    if [ $i -eq 10 ]; then
        echo ""
        echo "✗ Backend unhealthy"
        $SUDO_CMD journalctl -u $SERVICE_NAME --no-pager -n 20
        exit 1
    fi
done

echo ""
echo "========================================="
echo "✓ Deployment successful!"
echo "========================================="
echo "Domain:  $DOMAIN"
echo "Status:  sudo systemctl status $SERVICE_NAME"
echo "Logs:    sudo journalctl -u $SERVICE_NAME -f"
echo "Restart: sudo systemctl restart $SERVICE_NAME"
echo "========================================="
