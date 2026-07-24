import urllib.parse


ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def normalize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        raise TypeError("domain must be a string")

    domain = domain.strip()
    if not domain:
        raise ValueError("domain must not be empty")

    if "://" not in domain:
        domain = f"https://{domain}"

    parsed = urllib.parse.urlparse(domain)

    if parsed.scheme not in ALLOWED_URL_SCHEMES or not parsed.netloc:
        raise ValueError("domain must be an HTTP(S) URL or domain")

    path = parsed.path.rstrip("/")
    base_path = f"{path}/" if path else "/"

    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        base_path,
        "",
        "",
        ""
    ))


def is_http_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in ALLOWED_URL_SCHEMES and bool(parsed.netloc)
