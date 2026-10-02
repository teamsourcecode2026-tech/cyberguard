import whois

domain = "google.com"

try:
    info = whois.whois(domain)
    print("Raw WHOIS result:")
    print(info)
    print("\nCreation date field:", info.creation_date)
except Exception as e:
    print(f"WHOIS lookup failed with error: {type(e).__name__}: {e}")