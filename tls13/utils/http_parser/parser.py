import re

def parse(request_message):
    pattern = r'(GET|POST) /(.*) HTTP/([1-2]\.[1-2])\r?\n'

    http_method = None
    request_url = None
    http_version = None

    params = {}

    m1 = re.search(pattern, request_message)
    if m1 is not None:
        http_method = m1.group(1)
        request_url = m1.group(2)
        http_version = m1.group(3)

        params['http_method'] = http_method
        params['request_url'] = request_url
        params['http_version'] = http_version

    request_headers = re.findall("([A-Z][a-zA-Z0-9\-]*): (.*)\n", request_message)
    for header in request_headers:
        params[header[0]] = header[1]

    return params
