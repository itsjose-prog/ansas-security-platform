# core/remediation_engine.py

REMEDIATION_KNOWLEDGE_BASE = {
    "ftp": {
        "action": "Disable Anonymous FTP & Switch to SFTP",
        "steps": "1. Edit /etc/vsftpd.conf: Set 'anonymous_enable=NO'. 2. Install OpenSSH-server to use SFTP on port 22.",
        "risk_fix": "Prevents unauthenticated data exfiltration over cleartext.",
        "risk_level": "High"
    },
    "telnet": {
        "action": "Decommission Telnet Immediately",
        "steps": "1. Run 'sudo systemctl stop telnet'. 2. Enable SSH as a secure alternative.",
        "risk_fix": "Eliminates cleartext credential sniffing.",
        "risk_level": "Critical"
    },
    "http": {
        "action": "Enforce HTTPS (TLS 1.3)",
        "steps": "1. Install an SSL certificate (Let's Encrypt). 2. Update Web Server config to redirect port 80 to 443.",
        "risk_fix": "Secures data in transit against MITM attacks.",
        "risk_level": "Medium"
    },
    "mysql": {
        "action": "Harden Database Access",
        "steps": "1. Run 'mysql_secure_installation'. 2. Bind MySQL to localhost only. 3. Disable the root remote login.",
        "risk_fix": "Prevents unauthorized remote database brute-forcing.",
        "risk_level": "High"
    }
}

def get_remediation(product_name):
    product_lower = product_name.lower()
    for key, advice in REMEDIATION_KNOWLEDGE_BASE.items():
        if key in product_lower:
            return advice
            
    # Default fallback
    return {
        "action": "Standard Patching & Updates",
        "steps": "1. Check vendor website for the latest stable security patch. 2. Apply via package manager (apt/yum).",
        "risk_fix": "Reduces attack surface by closing known CVEs.",
        "risk_level": "Standard"
    }