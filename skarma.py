import sys
import argparse

import requests
import dns.resolver
import dns.name
import whois

from datetime import datetime


CNAME_RDTYPE = 5
def gen_cnames(subdomain):
    ans = dns.resolver.query(target, 'CNAME')
    for ans_rec in ans.response.answer:
        for rec_data in ans_rec.items:
            if rec_data.rdtype == CNAME_RDTYPE:
                yield rec_data.to_text()


FINGERPRINTS = None
def check_cloud(domain):
    if len(domain.split('.')) < 4:
        return False

    cloud_domain = domain[domain.find('.') + 1:]
    if not FINGERPRINTS.has_key(cloud_domain):
        return False

    urls = ['http://{}'.format(domain), 'https://{}'.format(domain)]
    results = map(requests.get, urls)
    for res in results:
        if (300 <= res.status_code < 500 and
                FINGERPRINTS[cloud_domain]['fingerprint'] in res.text):
            return True
    return False


NOW = None
def check_expired(domain):
    try:
        w = whois.whois(domain)
    except whois.parser.PywhoisError:
        return False
    return NOW > w.expiration_date


def check_available(domain):
    try:
        ans = dns.resolver.query(domain)
    except Exception as e:
        if str(e).startswith('None of DNS query names exist: '):
            ns_exists = False
        else:
            raise
    else:
        ns_exists = True

    # check cloud services
    if ns_exists and check_cloud(domain):
        return True

    # check whois for expiration
    if check_expired(domain):
        return True

    # if name server does not exist, the domain has not been purchased yet
    # which (probably) means that the domain can be purchased
    return not ns_exists


def gen_available(fqdn):
    """gen_available
    generatle available cnames of the specified fqdn
    """
    ans = dns.resolver.query(target, 'CNAME')
    cnames = gen_cnames(fqdn)

    return filter(check_available, cnames)


def init():
    global NOW
    global FINGERPRINTS

    NOW = datetime.now()
    with open('./fingerprints.json') as f:
        FINGERPRINTS = json.loads(f.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=str,
                        help='target to check for subdomain takeover vulnerability')
    parser.add_argument('--web', '-w', dest='is_web', default=False, action='store_true')
    args = parser.parse_args()

    init()

    if not args.is_web:
        check_subdomain(args.target)
    else:
        check_web(args.target)
