bug bounty hunter
=================

Bug_Bounty_Hunter(BBH) was created to assist in quickly finding interesting information relating to domains.
BBH first scrapes links that the webite is using or calling not outside of its self.
BBH then takes those domains and runs the dig command to check for CNAMES. BBH then sends those domains to
WHOIS to check the expiration date and status of the domain. Finially we send a get request to those domains and return
the response codes.

Installation
------------

    pip install -e git://github.com/anpseftis/bug_bounty_hunter.git#egg=bug_bounter_hunter


Usage
-----

     bug_bounty_hunter <DOMAIN>

E.g.

     bug_bounty_hunter https://www.google.com

Example output
______________

Links Scraped:

    +------+-----------------------------------------+
    | Type | Link                                    |
    +------+-----------------------------------------+
    |a     |http://www.iana.org/domains/example      |
    +------+-----------------------------------------+

Dig Results:

    +---------------+-------+------------------------+
    | Domain        | Type  | Resolves To            |
    +---------------+-------+------------------------+
    |www.iana.org.  |CNAME  |ianawww.vip.icann.org.  |
    +---------------+-------+------------------------+

WHOIS Results:

    +----------+-----------------+-------------------+
    | Host     | Expiration Date | Status            |
    +----------+-----------------+-------------------+
    |IANA.ORG  |08-12-17         |Active             |
    +----------+-----------------+-------------------+

Status Return:

    +-------------------------------------+----------+
    | Link                                | Status   |
    +-------------------------------------+----------+
    | http://www.iana.org/domains/example | 200      |
    +-------------------------------------+----------+