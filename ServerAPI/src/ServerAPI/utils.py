NONE, LAX, STRICT = "None", "Lax", "Strict" # cookie security levels

def parse_cookies(headers: dict[str, str]) -> dict[str, str]:
    """
    Parse cookies from the headers.
    """
    cookies = headers.get("cookie", None)
    if cookies is None:
        return {}
    cookie_dict = {}
    for cookie in cookies.split(";"):
        if "=" in cookie:
            key, value = cookie.split("=", 1)
            cookie_dict[key.strip()] = value.strip()
        else:
            # Handle cookies without a value
            cookie_dict[cookie.strip()] = ""
    return cookie_dict

def format_session_token(token: str, level: str, use_tls: bool) -> str:
    """
    Format a session token for a TCP connection.
    """
    if use_tls:
        return f"sessionToken={token}; Path=/; HttpOnly; Secure; SameSite={level};"
    return f"sessionToken={token}; Path=/; HttpOnly; SameSite={level};"