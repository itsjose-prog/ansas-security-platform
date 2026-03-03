import ssl
import socket
from datetime import datetime

def check_certificate_expiry(hostname, port):
    """
    Connects to a host/port, retrieves the SSL certificate, 
    and checks if it is expired.
    """
    context = ssl.create_default_context()
    
    # Crucial for pfSense: We ignore hostname mismatches and 
    # allow self-signed certs so the scan doesn't crash.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the certificate metadata
                cert = ssock.getpeercert()
                
                # Extract the 'notAfter' date string
                # Example format: 'Sep 23 12:14:06 2024 GMT'
                expiry_str = cert.get('notAfter')
                if not expiry_str:
                    return "No certificate found"

                # Convert string to a Python datetime object
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                today = datetime.now()

                if expiry_date < today:
                    days_expired = (today - expiry_date).days
                    return f"EXPIRED: {days_expired} days ago ({expiry_date.strftime('%Y-%m-%d')})"
                else:
                    days_left = (expiry_date - today).days
                    return f"Valid: {days_left} days remaining"

    except Exception as e:
        return f"Scan Failed: {str(e)}"