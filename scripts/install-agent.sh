#!/bin/bash

set -e

check_pkg() {
	if ! command -v "$1" &>/dev/null; then
		echo "$1 could not be found, please install it first"
		exit 1
	fi
}

# check if curl and jq are installed
check_pkg curl
check_pkg jq

# check if running user is root
if [ "$EUID" -ne 0 ]; then
	echo "Please run the script as root"
	exit 1
fi

# check if system is using systemd
if [ -d "/etc/systemd/system" ]; then
	echo "System is using systemd"
else
	echo "Unsupported init system, currently only systemd is supported"
	exit 1
fi

# check variables
if [ -z "$AGENT_NAME" ]; then
	echo "AGENT_NAME is not set"
	exit 1
fi
if [ -z "$AGENT_PORT" ]; then
	echo "AGENT_PORT is not set"
	exit 1
fi
if [ -z "$AGENT_CA_CERT" ]; then
	echo "AGENT_CA_CERT is not set"
	exit 1
fi
if [ -z "$AGENT_SSL_CERT" ]; then
	echo "AGENT_SSL_CERT is not set"
	exit 1
fi

# init variables
arch=$(uname -m)
if [ "$arch" = "x86_64" ]; then
	filename="godoxy-agent-linux-amd64"
elif [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then
	filename="godoxy-agent-linux-arm64"
else
	echo "Unsupported architecture: $arch, expect x86_64 or aarch64/arm64"
	exit 1
fi
repo="yusing/godoxy"
install_path="/usr/local/bin"
name="godoxy-agent"
bin_path="${install_path}/${name}"
env_file="/etc/${name}.env"
service_file="/etc/systemd/system/${name}.service"
log_path="/var/log/godoxy/${name}.log"
log_dir=$(dirname "$log_path")
data_path="/var/lib/${name}"

# check if install path is writable
if [ ! -w "$install_path" ]; then
	echo "Install path is not writable, please check the permissions"
	exit 1
fi

# check if service path is writable
if [ ! -w "$(dirname "$service_file")" ]; then
	echo "Service path is not writable, please check the permissions"
	exit 1
fi

# check if env file is writable
if [ ! -w "$(dirname "$env_file")" ]; then
	echo "Env file is not writable, please check the permissions"
	exit 1
fi

# check if command is uninstall
if [ "$1" = "uninstall" ]; then
	echo "Uninstalling the agent"
	systemctl disable --now $name || true
	rm -f $bin_path
	rm -f $env_file
	rm -f $service_file
	rm -rf $data_path
	echo "Note: Log file at $log_path is preserved"
	systemctl daemon-reload
	echo "Agent uninstalled successfully"
	exit 0
fi

echo "Finding the latest agent binary"
api_response=$(curl -s -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/$repo/releases/latest)
if [ -z "$api_response" ]; then
	echo "Failed to get response from GitHub API"
	exit 1
fi

bin_url=$(echo "$api_response" | jq -r '.assets[] | select(.name | contains("'$filename'")) | .browser_download_url')
if [ -z "$bin_url" ] || [ "$bin_url" = "null" ]; then
	echo "Failed to find binary for architecture: $arch"
	exit 1
fi

echo "Downloading the agent binary from $bin_url"
if ! curl -L -f "$bin_url" -o $bin_path; then
	echo "Failed to download binary"
	exit 1
fi

echo "Making the agent binary executable"
chmod +x $bin_path

echo "Creating the environment file"
cat <<EOF >$env_file
AGENT_NAME="${AGENT_NAME}"
AGENT_PORT="${AGENT_PORT}"
AGENT_CA_CERT="${AGENT_CA_CERT}"
AGENT_SSL_CERT="${AGENT_SSL_CERT}"
EOF
chmod 600 $env_file

echo "Creating the data directory"
mkdir -p $data_path
chmod 700 $data_path

echo "Creating log directory"
mkdir -p "$log_dir"
touch "$log_path"
chmod 640 "$log_path"

echo "Registering the agent as a service"
cat <<EOF >$service_file
[Unit]
Description=GoDoxy Agent
After=network.target
After=docker.socket

[Service]
Type=simple
ExecStart=${bin_path}
EnvironmentFile=${env_file}
WorkingDirectory=${data_path}
Restart=always
RestartSec=10
StandardOutput=append:${log_path}
StandardError=append:${log_path}

# Security settings
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths=${data_path} ${log_path}

# User and group
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
chmod 644 $service_file

systemctl daemon-reload
echo "Enabling and starting the agent service"
if ! systemctl enable --now $name; then
	echo "Failed to enable and start the service. Check with: systemctl status $name"
	exit 1
fi
echo "Checking if the agent service is started successfully"
if [ "$(systemctl is-active $name)" != "active" ]; then
	echo "Agent service failed to start, details below:"
	systemctl status $name
	more $log_path
	exit 1
fi

echo "Agent installed successfully"
