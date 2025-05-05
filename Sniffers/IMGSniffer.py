from mitmproxy import http
import os
import re

def check_extension(ext: str) -> str:
    return "jpg" if ext.lower() == "jpeg" else ext.lower()

def sanitize_filename(url: str) -> str:
    # Elimina caracteres inválidos para nombres de archivos
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', url)

def save_image(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def response(flow: http.HTTPFlow):
    content_type = flow.response.headers.get("content-type", "")
    if "image" in content_type:
        try:
            extension = content_type.split("/")[-1].split(";")[0]
            extension = check_extension(extension)

            url = flow.request.pretty_url
            file_name = sanitize_filename(url)
            full_path = f"images/{file_name}.{extension}"

            save_image(full_path, flow.response.content)
            print(f"\n\t[✔] Image saved in: {full_path}")
        except Exception as e:
            print(f"\n\t[✘] Error saving image: {e}")
        pass




