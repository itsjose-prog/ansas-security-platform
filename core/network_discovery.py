import requests
import re
import subprocess

def get_default_gateway():
    """
    ANSAS Auto-Discovery Engine:
    Automatically sniffs the local routing table to find the gateway IP.
    """
    try:
        # Executes 'ip route' to find the default exit point of the network
        result = subprocess.check_output(["ip", "route"], encoding="utf-8")
        match = re.search(r"default via ([\d\.]+)", result)
        if match:
            gateway_ip = match.group(1)
            print(f"[+] ANSAS Auto-Discovery: Default Gateway found at {gateway_ip}")
            return gateway_ip
        return None
    except Exception as e:
        print(f"[-] Gateway Sniffer Failed: {e}")
        return None

def detect_and_pivot(target_ip=None):
    """
    Follows HTTP 301/302 redirects to identify hidden management ports.
    If no IP is provided, it triggers the Auto-Discovery engine first.
    """
    # Auto-sniff if IP isn't provided
    if not target_ip:
        target_ip = get_default_gateway()
        if not target_ip:
            return "80" # Fallback to standard port

    url = f"http://{target_ip}"
    
    try:
        # Step 1: Send request without following redirects automatically
        # We need to see the 'Location' header ourselves
        response = requests.get(url, allow_redirects=False, timeout=5)
        
        # Step 2: Check for 301 or 302 codes (Targeting infrastructure like pfSense)
        if response.status_code in [301, 302]:
            new_location = response.headers.get('Location')
            print(f"[!] Redirect Detected: {new_location}")
            
            # Step 3: Extract the port if it's non-standard (e.g., :635)
            port_match = re.search(r':(\d+)', new_location)
            
            if port_match:
                new_port = port_match.group(1)
                print(f"[+] Pivoting Scan to Hidden Port: {new_port}")
                return new_port
            else:
                print("[+] Redirected to standard secure port.")
                return "443" 
                
        else:
            print("[+] No redirect. Standard port 80 is active.")
            return "80"

    except requests.exceptions.RequestException as e:
        print(f"[-] Connection Failed to {target_ip}: {e}")
        return "80"