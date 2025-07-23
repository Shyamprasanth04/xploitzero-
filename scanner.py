import requests
from requests.exceptions import RequestException

def check_security_headers(url):
    headers_to_check = [
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
    ]
    results = {}
    try:
        response = requests.get(url, timeout=10)
        for header in headers_to_check:
            results[header] = response.headers.get(header, None)
        results['status_code'] = response.status_code
    except RequestException as e:
        results['error'] = str(e)
    return results


def check_xss(url):
    import re
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    xss_payloads = [
        '<script>alert(1)</script>',
        '" onmouseover=alert(1) x="',
        "'><img src=x onerror=alert(1)>",
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<math href="javascript:alert(1)">CLICK',
        '<img src=1 href=1 onerror=alert(1)>',
        'javascript:alert(1)',
        'alert(1)',
    ]
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        qs = {'xss_test': [xss_payloads[0]]}
    results = []
    for payload in xss_payloads:
        if not qs:
            test_qs = {'xss_test': [payload]}
        else:
            test_qs = {k: [payload] for k in qs}
        new_query = urlencode(test_qs, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        try:
            resp = requests.get(new_url, timeout=10)
            reflected = payload in resp.text
            results.append({
                'payload': payload,
                'tested_url': new_url,
                'reflected': reflected,
                'vulnerable': reflected,  # For now, treat reflection as possible vuln
                'evidence': resp.text[:1000] if reflected else ''
            })
        except RequestException as e:
            results.append({'payload': payload, 'tested_url': new_url, 'error': str(e)})
    summary = any(r['vulnerable'] for r in results)
    # Return the first reflected payload as main evidence
    main = next((r for r in results if r['vulnerable']), results[0])
    return {'summary': summary, 'details': results, 'vulnerable': summary, 'payload': main['payload'], 'tested_url': main['tested_url'], 'evidence': main.get('evidence', '')}


def check_sqli(url):
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    sqli_payloads = [
        "'", '"', "' OR '1'='1", '" OR "1"="1', ' OR 1=1--', ' OR 1=1#',
        "' OR 1=1-- -", ' OR TRUE--', ' OR 1=1/*', 'admin"--',
        'admin");--', 'admin");#', 'admin");/*',
        '1) OR 1=1--', '1)) OR (1=1--', '1)) OR (1=1)#',
        '1)) OR (1=1)/*', 'admin\\', 'admin\\',
    ]
    error_signatures = [
        'you have an error in your sql syntax',
        'warning: mysql',
        'unclosed quotation mark after the character string',
        'quoted string not properly terminated',
        'sql syntax',
        'mysql_fetch',
        'syntax error',
        'odbc',
        'ora-',
        'invalid query',
        'pg_query',
        'fatal error',
        'mysql_num_rows()',
        'supplied argument is not a valid',
        'Microsoft OLE DB Provider for ODBC Drivers',
        'Microsoft OLE DB Provider for SQL Server',
        'Incorrect syntax near',
        'Unexpected end of command',
        'DB2 SQL error:',
        'Sybase message:',
        'JDBC',
        'System.Data.SqlClient.SqlException',
        'com.mysql.jdbc.exceptions',
        'SQLite3::SQLException',
        'MySqlException',
        'PdoException',
    ]
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        qs = {'sqli_test': ['']}  # Add dummy param if none
    results = []
    for payload in sqli_payloads:
        test_qs = {k: [payload] for k in qs}
        new_query = urlencode(test_qs, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        try:
            resp = requests.get(new_url, timeout=10)
            found = False
            matched_sig = None
            for sig in error_signatures:
                if sig in resp.text.lower():
                    found = True
                    matched_sig = sig
                    break
            results.append({
                'payload': payload,
                'tested_url': new_url,
                'vulnerable': found,
                'error_signature': matched_sig,
                'evidence': resp.text[:1000] if found else ''
            })
        except RequestException as e:
            results.append({
                'payload': payload,
                'tested_url': new_url,
                'vulnerable': False,
                'error': str(e)
            })
    summary = any(r['vulnerable'] for r in results)
    return {'summary': summary, 'details': results}


def check_open_redirect(url):
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    redirect_params = ['redirect', 'url', 'next', 'return', 'dest', 'destination', 'continue']
    payload = 'https://evil.com'
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    found_param = None
    for param in redirect_params:
        if param in qs:
            found_param = param
            break
    if not found_param:
        # If no redirect param, add one
        qs = {'redirect': [payload]}
        found_param = 'redirect'
    else:
        qs[found_param] = [payload]
    new_query = urlencode(qs, doseq=True)
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    try:
        resp = requests.get(new_url, allow_redirects=False, timeout=10)
        location = resp.headers.get('Location', '')
        vulnerable = payload in location
        return {'tested_url': new_url, 'param': found_param, 'vulnerable': vulnerable, 'location': location}
    except RequestException as e:
        return {'error': str(e)}


def check_directory_listing(url):
    from urllib.parse import urljoin
    common_dirs = ['/', '/uploads/', '/files/', '/backup/', '/.git/', '/.svn/']
    findings = []
    for d in common_dirs:
        test_url = urljoin(url, d)
        try:
            resp = requests.get(test_url, timeout=10)
            indicators = ['Index of', 'Parent Directory', '<title>Index of']
            vulnerable = any(ind in resp.text for ind in indicators)
            findings.append({'url': test_url, 'vulnerable': vulnerable})
        except RequestException as e:
            findings.append({'url': test_url, 'vulnerable': False, 'error': str(e)})
    summary = any(f['vulnerable'] for f in findings)
    return {'summary': summary, 'details': findings}


def check_admin_panels(url):
    from urllib.parse import urljoin
    admin_paths = ['/admin', '/admin/', '/administrator', '/login', '/admin/login', '/cpanel', '/backend']
    findings = []
    for path in admin_paths:
        test_url = urljoin(url, path)
        try:
            resp = requests.get(test_url, timeout=10)
            accessible = resp.status_code == 200
            findings.append({'url': test_url, 'accessible': accessible, 'status_code': resp.status_code})
        except RequestException as e:
            findings.append({'url': test_url, 'accessible': False, 'error': str(e)})
    summary = any(f['accessible'] for f in findings)
    return {'summary': summary, 'details': findings}


def scan_all(url, selected_checks=None):
    results = {}
    if not selected_checks or selected_checks.get('headers'):
        results['headers'] = check_security_headers(url)
    if not selected_checks or selected_checks.get('xss'):
        results['xss'] = check_xss(url)
    if not selected_checks or selected_checks.get('sqli'):
        results['sqli'] = check_sqli(url)
    if not selected_checks or selected_checks.get('open_redirect'):
        results['open_redirect'] = check_open_redirect(url)
    if not selected_checks or selected_checks.get('directory_listing'):
        results['directory_listing'] = check_directory_listing(url)
    if not selected_checks or selected_checks.get('admin_panels'):
        results['admin_panels'] = check_admin_panels(url)
    return results 