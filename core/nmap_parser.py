import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path):
    """
    Parses an Nmap XML file and extracts asset and vulnerability data.
    Target: To be used by the ANSAS Data Acquisition Module.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        return {"error": f"Failed to parse XML: {str(e)}"}

    scanned_hosts = []

    # Iterate through each 'host' tag in the XML
    for host in root.findall('host'):
        host_data = {
            'ip_address': None,
            'hostnames': [],
            'services': [],
            'os_match': None
        }

        # 1. Get IP Address
        address = host.find('address')
        if address is not None:
            host_data['ip_address'] = address.get('addr')

        # 2. Get Hostnames
        hostnames = host.find('hostnames')
        if hostnames is not None:
            for hn in hostnames.findall('hostname'):
                host_data['hostnames'].append(hn.get('name'))

        # 3. Get Ports and Services
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                
                # We only care about open ports for risk assessment
                if state == 'open':
                    service = port.find('service')
                    service_info = {
                        'port': port_id,
                        'protocol': protocol,
                        'name': 'unknown',
                        'product': 'unknown',
                        'version': 'unknown'
                    }
                    
                    if service is not None:
                        service_info['name'] = service.get('name', 'unknown')
                        service_info['product'] = service.get('product', 'unknown')
                        service_info['version'] = service.get('version', 'unknown')

                    host_data['services'].append(service_info)

        # Only add hosts that are actually up or have open ports
        if host_data['ip_address']:
            scanned_hosts.append(host_data)

    return scanned_hosts

# --- QUICK TEST BLOCK ---
# This allows us to run this file directly to test it.
if __name__ == "__main__":
    # Create a dummy XML file for testing if one doesn't exist
    import os
    dummy_xml = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open" reason="syn-ack" reason_ttl="0"/>
                    <service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/>
                </port>
                <port protocol="tcp" portid="22">
                    <state state="open" reason="syn-ack" reason_ttl="0"/>
                    <service name="ssh" product="OpenSSH" version="7.6p1" method="probed" conf="10"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """
    
    with open("test_scan.xml", "w") as f:
        f.write(dummy_xml)
        
    print("Testing Parser on dummy data...")
    result = parse_nmap_xml("test_scan.xml")
    print(result)
    
    # Clean up
    os.remove("test_scan.xml")