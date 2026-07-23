FROM kalilinux/kali-rolling

# Avoid interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

# Update system and install basic packages + Python
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    git \
    curl \
    wget \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Core security tools ─────────────────────────────────────────────────────
# Installed in batches; retry loop handles transient network failures.
# Covers: network scanning, discovery, web, SSL, SMB, credentials, exploitation.
RUN apt-get update && \
    for i in 1 2 3 4 5; do \
        apt-get install -y --fix-missing \
            nmap \
            masscan \
            arp-scan \
            netcat-openbsd \
            traceroute \
            dnsutils \
            whois \
            iputils-ping \
            net-tools \
            iproute2 \
            snmp \
            snmp-mibs-downloader \
            ldap-utils \
            nikto \
            dirb \
            gobuster \
            whatweb \
            sslyze \
            sslscan \
            enum4linux \
            smbclient \
            metasploit-framework \
            hydra \
            medusa \
            john \
            hashcat \
            sqlmap \
            wpscan \
            exploitdb \
            ssh-audit \
            netcat-traditional \
            aircrack-ng \
            wifite \
            bluez \
            set \
            impacket-scripts \
            crackmapexec \
            nuclei \
            ffuf \
            amass \
            theharvester \
            peass \
        && break || \
        (echo "apt-get install failed, retrying in 10s (attempt $i)..." && sleep 10 && apt-get update); \
    done && \
    rm -rf /var/lib/apt/lists/*

# Fix SNMP MIBs config
RUN sed -i 's/^mibs :/#mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true

# Set up app directory
WORKDIR /app

# Copy dependency file first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy the rest of the application
COPY . .

# Setup system configuration and data directories
RUN mkdir -p /etc/mcp-kali /var/lib/mcp/artifacts /var/lib/mcp/memory && \
    chmod 775 /var/lib/mcp && \
    echo '{"allowed_cidrs":["10.0.0.0/8","192.168.0.0/16","172.16.0.0/12","127.0.0.1/32","0.0.0.0/0"],"allow_destructive":true}' > /etc/mcp-kali/scope.json && \
    python3 -c "import json, secrets, datetime; data = {'id': 'kali-docker-test', 'token': 'test_token', 'created': datetime.datetime.now().isoformat()}; json.dump(data, open('/etc/mcp-kali/enroll.json', 'w'))"

# Expose port
EXPOSE 5000

# Default command
CMD ["python3", "-m", "mcp_server.api"]
