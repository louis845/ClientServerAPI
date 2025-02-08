from typing import Optional

def parse_cookies(cookie_header: Optional[str]) -> dict[str, str]:
    """
    Parses a Cookie header string into a dictionary of key-value pairs.

    Args:
        cookie_header (Optional[str]): The Cookie header string.

    Returns:
        dict[str, str]: Dictionary representing the parsed cookies.
    """
    cookies: dict[str, str] = {}
    if cookie_header is None:
        return cookies

    cookie_pairs = cookie_header.split(';')
    for cookie in cookie_pairs:
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            cookies[key.strip()] = value.strip()
    return cookies