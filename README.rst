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

    -----------Lets Scrape all External Links.----------
    +External Links------------------------------+
    | Type | Link                                |
    +------+-------------------------------------+
    | a    | http://www.iana.org/domains/example |
    +------+-------------------------------------+

    -----------External Links Scraping Complete.---------

    -----------Lets send all the domains to dig!---------
    +Dig------------+-------+------------------------+
    | Domain        | Type  | Resolves To            |
    +---------------+-------+------------------------+
    | www.iana.org. | CNAME | ianawww.vip.icann.org. |
    +---------------+-------+------------------------+

    -----------Dig Results Complete!----------------------

    -----------Lets do a WHOIS on the Domains!------------

    +Whois-----+-----------------+--------+
    | Host     | Expiration Date | Status |
    +----------+-----------------+--------+
    |          |                 |        |
    +----------+-----------------+--------+
    | IANA.ORG | 08-12-17        |        |
    +----------+-----------------+--------+

    -----------WHOIS COMPLETE------------------------------

    -----------URL Status Below.---------------------------

    +Link Status--------------------------+--------+
    | Link                                | Status |
    +-------------------------------------+--------+
    | http://www.iana.org/domains/example | 200    |
    +-------------------------------------+--------+
    -----------Script Complete------------------------------

