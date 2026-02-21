# core/compliance_engine.py

def evaluate_compliance(scan_data):
    """
    Directly maps technical Nmap findings to Kenya Data Protection Act 2019.
    """
    compliance_results = {
        "status": "Compliant",
        "violations": [],
        "risk_level": "Low"
    }
    
    for host in scan_data:
        ip = host.get('ip_address', 'Unknown')
        for svc in host.get('services', []):
            port = svc.get('port')
            product = svc.get('product', '').lower()
            vulns = svc.get('vulnerabilities', [])
            
            # --- SECTION 41: Security of Personal Data ---
            # Technical Measure: High/Critical CVEs mean technical measures are failing.
            for v in vulns:
                score = float(v.get('cvss_score', 0))
                if score >= 7.0:
                    compliance_results["status"] = "Non-Compliant"
                    compliance_results["risk_level"] = "High"
                    compliance_results["violations"].append({
                        "ip": ip,
                        "section": "Section 41",
                        "provision": "Security of Personal Data",
                        "finding": f"Critical vulnerability {v.get('id')} on port {port}",
                        "law": "Controllers must implement appropriate technical measures to prevent unauthorized access."
                    })

            # --- SECTION 41(2)(a): Encryption Requirement ---
            # Unencrypted services found in a scan.
            unencrypted = ['telnet', 'ftp', 'http', 'mysql', 'postgresql', 'vnc']
            if any(u in product for u in unencrypted):
                compliance_results["status"] = "Non-Compliant"
                if compliance_results["risk_level"] != "High":
                    compliance_results["risk_level"] = "Medium"
                
                compliance_results["violations"].append({
                    "ip": ip,
                    "section": "Section 41(2)(a)",
                    "provision": "Pseudonymisation and Encryption",
                    "finding": f"Unencrypted protocol '{product}' detected on port {port}",
                    "law": "Mandates encryption of personal data to mitigate risks of data breaches."
                })

    return compliance_results