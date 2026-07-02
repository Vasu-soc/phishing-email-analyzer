import re
from typing import List
from urllib.parse import urlparse
from phishing_analyzer.detectors import BaseDetector, DetectionMatch

class URLDetector(BaseDetector):
    """
    Detects suspicious URLs, including HTTP links, URL shorteners, IP-address-based links,
    and suspicious domains using regex and domain list matches.
    """
    def __init__(self, shorteners: List[str], suspicious_tlds: List[str]):
        super().__init__(category="suspicious_url")
        self.shorteners = [s.lower() for s in shorteners]
        self.suspicious_tlds = [t.lower().lstrip('.') for t in suspicious_tlds]
        
        # Regex to find URLs in text
        # Matches http://..., https://... and www.domain...
        self.url_regex = re.compile(
            r'(https?://[^\s<>"]+|www\.[^\s<>"]+)',
            re.IGNORECASE
        )
        
        # Regex for IPv4 address host
        self.ip_regex = re.compile(
            r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        )

    def detect(self, subject: str, body: str) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        
        matches.extend(self._analyze_text(subject, "subject"))
        matches.extend(self._analyze_text(body, "body"))
        
        return matches

    def _analyze_text(self, text: str, location: str) -> List[DetectionMatch]:
        if not text:
            return []
            
        matches: List[DetectionMatch] = []
        found_urls = self.url_regex.finditer(text)
        
        for url_match in found_urls:
            raw_url = url_match.group(0)
            start, end = url_match.span()
            
            # Clean up trailing punctuation that regex might accidentally grab
            clean_url = raw_url.rstrip('.,;!?()[]{}')
            # Adjust end index based on stripped chars
            end = start + len(clean_url)
            
            # Parse URL components
            parsed_url = clean_url
            if not parsed_url.lower().startswith(('http://', 'https://')):
                parsed_url = 'http://' + parsed_url
                
            try:
                parsed = urlparse(parsed_url)
                host = parsed.netloc.lower()
                # Strip port if present
                if ':' in host:
                    host = host.split(':')[0]
            except Exception:
                continue
                
            if not host:
                continue

            # Check 1: Insecure HTTP link
            if clean_url.lower().startswith("http://"):
                explanation = (
                    f"Insecure URL ('{clean_url}') detected in the {location}. "
                    "Phishing links often use insecure HTTP connections instead of HTTPS to avoid SSL/TLS setup."
                )
                matches.append(DetectionMatch(
                    category=self.category,
                    matched_text=clean_url,
                    pattern="http://",
                    explanation=explanation,
                    location=location,
                    start_index=start,
                    end_index=end
                ))

            # Check 2: IP-address-based link
            if self.ip_regex.match(host):
                explanation = (
                    f"IP-address-based URL ('{clean_url}') detected in the {location}. "
                    "Legitimate companies use registered domains. IP addresses are used to bypass domain reputation checks."
                )
                matches.append(DetectionMatch(
                    category=self.category,
                    matched_text=clean_url,
                    pattern="IP address host",
                    explanation=explanation,
                    location=location,
                    start_index=start,
                    end_index=end
                ))
                # Skip further checks if it's an IP host to avoid TLD checks
                continue

            # Check 3: URL Shortener
            is_shortener = False
            for shortener in self.shorteners:
                if host == shortener or host.endswith('.' + shortener):
                    explanation = (
                        f"URL shortener ('{clean_url}') detected in the {location}. "
                        "URL shorteners hide the final destination of a link and are frequently used to mask malicious sites."
                    )
                    matches.append(DetectionMatch(
                        category=self.category,
                        matched_text=clean_url,
                        pattern=shortener,
                        explanation=explanation,
                        location=location,
                        start_index=start,
                        end_index=end
                    ))
                    is_shortener = True
                    break
            
            if is_shortener:
                continue

            # Check 4: Suspicious TLD
            domain_parts = host.split('.')
            if len(domain_parts) > 1:
                tld = domain_parts[-1]
                if tld in self.suspicious_tlds:
                    explanation = (
                        f"Suspicious TLD (.{tld}) detected in URL '{clean_url}' in the {location}. "
                        f"Phishing campaigns frequently utilize cheap or free TLDs like '.{tld}'."
                    )
                    matches.append(DetectionMatch(
                        category=self.category,
                        matched_text=clean_url,
                        pattern=f".{tld}",
                        explanation=explanation,
                        location=location,
                        start_index=start,
                        end_index=end
                    ))

            # Check 5: Lookalike Subdomain Spoofing (e.g. paypal.com.something.xyz)
            # If the host contains a brand name followed by multiple subdomains
            # Let's check if common trusted brand keywords (like paypal, google, netflix, microsoft, amazon, apple, chase, bankofamerica)
            # appear in the subdomains rather than as the primary domain name.
            trusted_brands = ["paypal", "google", "netflix", "microsoft", "amazon", "apple", "chase", "bankofamerica", "facebook", "instagram"]
            if len(domain_parts) > 2:
                # The primary domain name is domain_parts[-2] + '.' + domain_parts[-1] (e.g. example.com)
                # The subdomains are the parts before domain_parts[-2]
                subdomains = domain_parts[:-2]
                for brand in trusted_brands:
                    for sub in subdomains:
                        if brand in sub:
                            explanation = (
                                f"Possible domain spoofing ('{brand}' keyword found in subdomain of '{host}') in the {location}. "
                                "Attackers prefix legitimate brand names to malicious domains to deceive users."
                            )
                            matches.append(DetectionMatch(
                                category=self.category,
                                matched_text=clean_url,
                                pattern=brand,
                                explanation=explanation,
                                location=location,
                                start_index=start,
                                end_index=end
                            ))
                            break

        return matches
