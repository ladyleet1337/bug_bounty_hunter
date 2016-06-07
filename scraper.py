#!/usr/bin/env python

from bs4 import BeautifulSoup
import urlparse
import argparse
from termcolor import colored
import subprocess
import whois
from terminaltables import AsciiTable
from textwrap import wrap
import requests


parser = argparse.ArgumentParser()
parser.add_argument('url', type=str)
parser.add_argument('--element', '-e', type=str, action='append')
args = parser.parse_args()

parsed_url = urlparse.urlparse(args.url)
timeout = 1

try:
    response = requests.get(args.url, verify=False, timeout=timeout )
except requests.exceptions.ReadTimeout:
    print('Could not connect to "%s" within %s seconds' % (args.url, timeout))
    exit(1)

def link_filter(link):
    link = link[1]
    parsed_link = urlparse.urlparse(link)
    return parsed_link.netloc and parsed_link != parsed_url.netloc
print(colored('-----------Lets Scrape all External Links.----------', 'green'))
soup = BeautifulSoup(response.content, "html.parser")
links = set()
links.update([(elem.name, elem.attrs.get('href')) for elem in soup.find_all(args.element or True, href=True)])
links.update([(elem.name, elem.attrs.get('src')) for elem in soup.find_all(args.element or True, src=True)])
links = sorted(filter(link_filter, links), key=lambda e: [e[0], e[1]])

links.insert(0, ['Type', 'Link'])

table = AsciiTable(links, 'External Links')
print(table.table)

print('\n \n ')
print(colored('-----------External Links Scraping Complete.----------', 'red'))
print('\n')
print(colored('-----------Lets send all the domains to dig!----------', 'green'))
dig_data = []
hosts = set([urlparse.urlparse(link[1]).netloc for link in links if link])

dig_data.insert(0, ['Domain', 'Type', 'Resolves To'])
table = AsciiTable(dig_data, 'Dig')
table.inner_heading_row_border = False
max_width = table.column_max_width(0)

for host in hosts:
    if not host:
        continue
    results_for_host = subprocess.check_output(['dig',"+noall","+answer","ANY", host])
    result_list = results_for_host.strip().split('\n')
    for result in result_list:
        result_pieces = result.split()
        table.table_data.append([result_pieces[0], result_pieces[3], result_pieces[4]])

print(table.table)
print('\n \n ')
print(colored('-----------Dig Results Complete!----------', 'red'))
print('\n')
print('\n \n ')
print(colored('-----------Lets do a WHOIS on the Domains!----------', 'green'))
print('\n')
hosts = list(hosts)

whois_data = [['Host', 'Expiration Date', 'Status']]
while hosts:
    host, hosts = hosts[0], hosts[1:]
    try:
        result = whois.whois(host)
        d = colored(result.domain_name or host, 'red')
        if not isinstance(d, basestring):
            d = '\n'.join(map(lambda x: colored(x, 'red'), d))
        e = result.expiration_date
        if not e:
            e = []
        if not isinstance(e, list):
            e = [e]
        e = '\n'.join([colored(i, 'green') if isinstance(i, basestring) else colored(i.strftime('%d-%m-%y'), 'green') for i in e])
        s = result.status
        if not s:
            s = []
        if not isinstance(s, list):
            s = [s]
        s = '\n'.join([colored(x.split()[0] or 'unknown', 'blue') for x in s])
        if not isinstance(s, basestring):
            s = '\n'.join(map(lambda x: colored(x.split()[0], 'blue'), s))

        whois_data.append([d, e, s])
    except whois.parser.PywhoisError as e:
        print('skipping ' + host)
        i = host.find('.')
        if i == -1:
            break
        host = host[i+1:]
        if host not in hosts:
            hosts.append(host)
table = AsciiTable(whois_data, 'Whois')
print(table.table)
print('\n \n ')
print(colored('-----------WHOIS COMPLETE----------', 'red'))
print('\n')
print('\n \n ')
print(colored('-----------URL Status Below.----------', 'green'))
print('\n')
# Take all the urls and do a GET request and return the status code.
link_data = [['Link', 'Status']]
long_string = ('Link Status')
table = AsciiTable(link_data, 'Link Status')
#table = AsciiTable(link_data, 'Link Status')
# Calculate newlines.
max_width = table.column_max_width(1)

for link in links[1:]:
    try:
        link = urlparse.urlparse(link[1])
        link = link._replace(scheme='http').geturl()
        resp = requests.get(link)
        link_data.append([link, resp.status_code])
        # prints the int of the status code. Find more at httpstatusrappers.com :)
    except requests.ConnectionError:
        print("failed to connect")
print(table.table)
print(colored('-----------Script Complete----------', 'green'))