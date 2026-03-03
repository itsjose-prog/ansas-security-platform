from core.signatures import DEVICE_SIGNATURES

def identify_device(raw_metadata):
    """
    Scans metadata (SSL CN, Nginx Headers, etc.) for known signatures.
    """
    found_type = "Generic Host"
    found_brand = "Unknown"

    for category, brands in DEVICE_SIGNATURES.items():
        for brand, markers in brands.items():
            # Check if any marker exists in the raw metadata string
            if any(marker.lower() in raw_metadata.lower() for marker in markers):
                found_type = category.upper()
                found_brand = brand.capitalize()
                return f"{found_type}: {found_brand}"
    
    return f"{found_type}"