/**
 * Parses cookies from a header string into an object.
 * @param cookieHeader The Cookie header string.
 * @returns An object representing the cookies.
 */
export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
    const cookies: Record<string, string> = {};
    if (!cookieHeader) return cookies;

    const cookiePairs = cookieHeader.split(';');
    cookiePairs.forEach(cookie => {
        const [key, value] = cookie.split('=', 2);
        if (key && value) {
            cookies[key.trim()] = value.trim();
        }
    });
    return cookies;
}
