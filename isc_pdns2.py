#####
#####!/usr/bin/env python
#####
from collections import defaultdict, namedtuple
from pytz import timezone
import argparse
import sys
import csv
import urllib2
import datetime
import json
import re
import time

API_KEY = u'52945d505516302b1895268ec9f602612a01120e897dca120c6b4154ed291b6b'
BASE_URL = u'https://api.dnsdb.info/'
FROM_IP_URL = BASE_URL + u'lookup/rdata/ip/{value}/{rtype}?time_first_after=1514764800' #Dirty hack: 06-06-2018
FROM_DOMAIN_URL = BASE_URL + u'lookup/rrset/name/{value}/{rtype}?time_first_after=1514764800'
FROM_OWNER_URL = BASE_URL + u'lookup/rdata/name/{value}/{rtype}?time_first_after=1514764800?limit=100'
IP_RE = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
NETPREFIX_RE = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}')


FIELDS = {'rrname': 'name', 'rrtype': 'type', 'rdata': 'data',
          'count': 'count', '(zone_)?time_first': 'time_first',
          '(zone_)?time_last': 'time_last', 'bailiwick':
          'bailiwick'}

PDNSRecord = namedtuple('PDNSRecord', FIELDS.values())


class ISCLookup(object):
    def ipv4_lookup(self, ip, rtype='ANY'):
        """
        This method may be used to lookup the given ip. It has the following parameters:
        ip: the ip to lookup.

        If the input isn't a valid IP address this will raise a ValueError
        """
        if not IP_RE.match(str(ip)):
            raise ValueError('{} isn\'t a valid IPv4 address!'.format(ip))
        return self._request(FROM_IP_URL.format(value=str(ip), rtype=rtype))

    def netprefix_lookup(self, ip, prefix, rtype='ANY'):
        """
        This method may be used to lookup the given ip range, using the provided
        prefix, such as 1.2.3.4/24. It has the following parameters:
        ip: the ip to lookup.
        prefix: the prefix used
        """
        if not IP_RE.match(str(ip)):
            raise ValueError('{} isn\'t a valid IPv4 address!'.format(ip))
        try:
            int(prefix)
        except ValueError:
            raise ValueError('{} isn\'t a valid IPv4 prefix'.format(prefix))

        return self._request(FROM_IP_URL.format(value=ip + ',' + str(prefix), rtype=rtype))

    def domain_lookup(self, domain, rtype='ANY'):
        """
        This method may be used to lookup the given domain name. It has the
        following parameters:
        domain: the domain to lookup.
        """
        return self._request(FROM_DOMAIN_URL.format(value=domain, rtype=rtype))

    def owner_lookup(self, name, rtype='ANY'):
        """
        This method may be used to lookup the given owner name. It has the
        following parameters:
        name: the owner name to lookup.
        """
        return self._request(FROM_OWNER_URL.format(value=name, rtype=rtype))

    def _request(self, url):
        req = urllib2.Request(url)
        req.add_header(u'X-API-Key', API_KEY)
        req.add_header(u'Accept', 'application/json')
        try:
            resp = urllib2.urlopen(req)
            result = []

            for line in resp:
                data = json.loads(line)
                recorddata = {k: None for k in FIELDS.values()}
                for d in data:
                    for f in FIELDS:
                        if re.match(f, d):
                            recorddata[FIELDS[f]] = data[d]
                result.append(PDNSRecord(**recorddata))
            return result
        except urllib2.HTTPError as e:
            raise ValueError('No result for "{}": {}'.format(url, e))

            if e.code == 429:
                print("ABORT! ABORT!")
                sys.exit()


def to_datetime(timestamp):
    timestamp = float(timestamp)
    return datetime.datetime.fromtimestamp(timestamp, timezone('UTC'))


def main():
    parser = argparse.ArgumentParser(description='Turn a newline separated list of IP addresses or domains (e.g. one IP/domain per line) into a list containing historical DNS information. For IP addresses you will see which domains used to point to this IP. For domain names you will see which IP\'s this domain used to resolve to.')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default='-', help='The file containing the IP addresses or domains. If not supplied, stdin will be used')
    args = parser.parse_args()

    # Dirty hack:
    log = 'LOG_' + str(time.time()).split('.')[0]
    logf = open(log, 'w')

    result = defaultdict(list)
    pdns = ISCLookup()
    outfile = open('ip_output.csv', 'wb')
    out = csv.writer(outfile, delimiter='\t')
    for i, line in enumerate(args.infile):
        print line
        line = line.strip()

        logf.write(line + '\n')

        if '.' not in line:
            continue

        if not i % 100:
            sys.stderr.write('.')

        error = None

        if NETPREFIX_RE.search(line):
            try:
                result[line].extend(pdns.netprefix_lookup(*line.split('/'), rtype='NS'))
            except ValueError as error:
                pass

            try:
                result[line].extend(pdns.netprefix_lookup(*line.split('/'), rtype='A'))
            except ValueError as error:
                pass
        elif IP_RE.search(line):
            """
            try:
                result[line].extend(pdns.ipv4_lookup(line, 'NS'))
            except ValueError as error:
                pass
            """
            try:
                result[line].extend(pdns.ipv4_lookup(line, 'A'))
            except ValueError as error:
                pass
        else:
            try:
                result[line].extend(pdns.owner_lookup(line, 'NS'))
            except ValueError as error:
                pass

            try:
                result[line].extend(pdns.owner_lookup(line, 'SOA'))
            except ValueError as error:
                pass

        if not result[line]:
            sys.stderr.write(str(error) + '\n')

        for v in result[line]:
            print v
            if isinstance(v.data, list):
                if '-t' in sys.argv[1:]:
                    out.writerows(list((v.name, v.type, x, v.count, to_datetime(v.time_first), to_datetime(v.time_last)) for x in v.data))
                else:
                    out.writerows(list((v.name, v.type, x, v.count, v.time_first, v.time_last) for x in v.data))
            else:
                if '-t' in sys.argv[1:]:
                    out.writerow((v.name, v.type, v.data, v.count, to_datetime(v.time_first), to_datetime(v.time_last)))
                else:
                    out.writerow((v.name, v.type, v.data, v.count, v.time_first, v.time_last))

    logf.close()

if __name__ == '__main__':
    main()
