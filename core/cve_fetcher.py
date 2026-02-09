import requests
import time
import logging

# Configure logging to track what happens in the background
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NVDFetcher:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            "User-Agent": "ANSAS-Security-Scanner/1.0"
        }
        if self.api_key:
            self.headers["apiKey"] = self.api_key

    def search_cves(self, product, version):
        """
        Searches NVD for CVEs matching a specific product and version.
        Returns a list of dictionaries with ID, Score, and Description.
        """
        # Construct the CPE (Common Platform Enumeration) string
        # This tells NVD exactly what software we are looking for.
        keyword = f"{product} {version}"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5  # Limit to top 5 to save bandwidth/time
        }

        try:
            # --- RATE LIMIT PROTECTION ---
            # NVD Rules: 
            # With Key: 0.6 seconds delay recommended
            # Without Key: 6.0 seconds delay recommended
            delay = 0.6 if self.api_key else 6.0
            time.sleep(delay) 

            logger.info(f"🔎 Searching NVD for: {keyword}")
            response = requests.get(self.base_url, headers=self.headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return self._parse_nvd_response(data)
            
            elif response.status_code == 403:
                logger.error("⛔ API Key Invalid or Rate Limit Exceeded.")
                return []
            
            else:
                logger.warning(f"⚠️ NVD Error: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"❌ Connection Failed: {str(e)}")
            return []

    def _parse_nvd_response(self, data):
        """
        Extracts clean data from the complex NVD JSON structure.
        """
        vuln_list = []
        
        # NVD 2.0 Structure: vulnerabilities -> cve -> metrics
        raw_items = data.get("vulnerabilities", [])

        for item in raw_items:
            cve_item = item.get("cve", {})
            cve_id = cve_item.get("id", "Unknown")
            
            # Extract Description
            descriptions = cve_item.get("descriptions", [])
            description_text = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_text = desc.get("value")
                    break

            # Extract CVSS Score (Try v3.1, then v3.0, then v2.0)
            metrics = cve_item.get("metrics", {})
            cvss_score = 0.0
            severity = "LOW"

            # Check CVSS v3.1 (The modern standard)
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "LOW")
            
            # Fallback to v3.0
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "LOW")
            
            # Fallback to v2.0 (Old legacy systems)
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "LOW")

            # Add to list
            vuln_list.append({
                "id": cve_id,
                "cvss_score": float(cvss_score),
                "severity": severity,
                "description": description_text[:200] + "..." # Truncate long text
            })

        return vuln_list