from bs4 import BeautifulSoup
import re
import urllib2
import urlparse
import argparse
from termcolor import colored
import subprocess
import whois
from terminaltables import AsciiTable
import requests
from requests.packages.urllib3 import exceptions


def get_with_timeout(url):
    timeout = 1
    response = None
    try:
        response = requests.get(url, verify=False, timeout=timeout)
    except requests.exceptions.ReadTimeout:
        print('Could not connect to "%s" within %s seconds' % (url, timeout))
    return response


def crawl(url):
    tocrawl = set([url])
    crawled = set([])
    crawled_list = []
    keywordregex = re.compile('<meta\sname=["\']keywords["\']\scontent=["\'](.*?)["\']\s/>')
    linkregex = re.compile('<a\s*href=[\'|"](.*?)[\'"].*?>')
    domain = urlparse.urlparse(url).netloc
    print(domain)

    while tocrawl: 
        error=0 
        try:
            crawling = tocrawl.pop()
            print crawling
        except IOError, error_code: 
	    error=1 
	    if error_code[0]=="http error": 
	        if error_code[1]==401: 
		    print "Password required" 
		elif error_code[1]==404: 
		    print "file not found" 
		elif error_code[1]==500: 
		    print "server is down" 
		else: 
		    print (error_code) 
	if error==1:
            continue
        response = get_with_timeout(crawling)
        if not response:
            continue 
	msg = response.content
        startPos = msg.find('<title>')
        if startPos != -1:
            endPos = msg.find('</title>', startPos+7)
            if endPos != -1:
                title = msg[startPos+7:endPos]
                print title
        keywordlist = keywordregex.findall(msg)
        if len(keywordlist) > 0:
            keywordlist = keywordlist[0]
            keywordlist = keywordlist.split(", ")
            print keywordlist
        links = linkregex.findall(msg)
        crawled.add(crawling)
        crawled_list.append(['', crawling])
        parsed_url = urlparse.urlparse(crawling)
        for link in (links.pop(0) for _ in xrange(len(links))):
            print(link)
            if link.find(domain) < 0:
                continue
            if link.startswith('/'):
                link = 'http://' + parsed_url[1] + link
            elif link.startswith('#'):
                link = 'http://' + parsed_url[1] + url[2] + link
            elif not link.startswith('http'):
                link = 'http://' + parsed_url[1] + '/' + link
            if link not in crawled:
                tocrawl.add(link)	

    return crawled_list


def hunt():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str)
    parser.add_argument('--element', '-e', type=str, action='append')
    args = parser.parse_args()

    # Allow access to sites that have http and https
    requests.packages.urllib3.disable_warnings()

    parsed_url = urlparse.urlparse(args.url)
    response = get_with_timeout(args.url)
    if not response:
        exit(1)

    def link_filter(link):
        link = link[1]
        parsed_link = urlparse.urlparse(link)
        return parsed_link.netloc and parsed_link != parsed_url.netloc

    print(colored('-----------Lets Scrape all External Links.----------', 'green'))
    soup = BeautifulSoup(response.content, "html.parser")
    links = set()

    def add_links(links, elems, attr):
        for elem in elems:
            link = elem.attrs.get(attr)
            # Exclude source domain
            if link.find(parsed_url.netloc) < 0:
                links.add((elem.name, link))

    add_links(links, soup.find_all(True, href=True), 'href')
    add_links(links, soup.find_all(True, src=True), 'src')
    links = sorted(filter(link_filter, links), key=lambda e: [e[0], e[1]])

    links.insert(0, ['Type', 'Link'])

    table = AsciiTable(links, 'External Links')
    table.inner_heading_row_border = True
    print(table.table)

    print('\n \n ')
    print(colored('-----------External Links Scraping Complete.----------', 'red'))
    print('\n')
    print(colored('-----------Lets send all the domains to dig!----------', 'green'))
    dig_data = []
    hosts = set([urlparse.urlparse(link[1]).netloc for link in links if link])

    dig_data.insert(0, ['Domain', 'Type', 'Resolves To'])
    table = AsciiTable(dig_data, 'Dig')
    table.inner_heading_row_border = True

    for host in hosts:
        if not host:
            continue
        results_for_host = subprocess.check_output(['dig', "+noall", "+answer", "ANY", host])
        result_list = results_for_host.strip().split('\n')
        for result in result_list:
            if not result:
                continue
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
            domain = result.domain_name or host
            if not isinstance(domain, basestring):
                domain = ', '.join(domain)
            d = colored(domain, 'red')
            e = result.expiration_date
            if not e:
                e = []
            if not isinstance(e, list):
                e = [e]
            e = '\n'.join(
                [colored(i, 'green') if isinstance(i, basestring) else colored(i.strftime('%d-%m-%y'), 'green') for i in
                 e])
            s = result.status
            if not s:
                s = []
            if not isinstance(s, list):
                s = [s]
            s = '\n'.join([colored(x.split()[0] or 'unknown', 'blue') for x in s if x.find('Prohibited') < 0])

            whois_data.append([d, e, s])
        except whois.parser.PywhoisError as e:
            print('skipping ' + host)
            i = host.find('.')
            if i == -1:
                break
            host = host[i + 1:]
            if host not in hosts:
                hosts.append(host)
    table = AsciiTable(whois_data, 'Whois')
    table.inner_heading_row_border = True
    table.inner_row_border = True
    print(table.table)
    print('\n \n ')
    print(colored('-------------------WHOIS COMPLETE----------------------', 'red'))
    print('\n')
    print('\n \n ')
    print(colored('-------------------URL Status Below.-------------------', 'green'))
    print('\n')

    def check_links(links):
        # Take all the urls and do a GET request and return the status code.
        link_data = [['Link', 'Status']]
        long_string = ('Link Status')
        table = AsciiTable(link_data, 'Link Status')
        table.inner_heading_row_border = True

        for link in links:
            try:
                link = urlparse.urlparse(link[1])
                link = link._replace(scheme='http').geturl()
                resp = requests.get(link, timeout=1)
                link_data.append([link, resp.status_code])
            except requests.ConnectionError:
                print("failed to connect")
            except requests.ReadTimeout:
                print("timed out")
        print(table.table)

    check_links(links[1:])
    print(colored('----------------------Checked Links-------------------', 'green'))

    crawled_links = crawl(args.url)
    check_links(crawled_links)

    print(colored('----------------------Script Complete-------------------', 'green'))


def main():
    hunt()
    return 0
