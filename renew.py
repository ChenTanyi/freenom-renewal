#!/usr/bin/env python3
#1st modify，try to add a line notify
import os
import re
import sys
import bs4
import json
import time
import requests
import logging
import urllib.parse

def lineNotifyMessage(token, msg):
      headers = {
          "Authorization": "Bearer " + token, 
          "Content-Type" : "application/x-www-form-urlencoded"
      }
	
      payload = {'message': msg}
      r = requests.post("https://notify-api.line.me/api/notify", headers = headers, params = payload)
      return r.status_code

    
def trim(s: str) -> str:
    return re.sub(r'\s+', ' ', s).strip()


def logging_table(titles, rows, length: int):
    format_func = lambda x: f'{x:<{length + 1}s}'
    #logging.info(' '.join(map(format_func, titles)))
    for row in rows:
       #logging.info(' '.join(map(format_func, row)))
       #LineNotify
       token: os.environ['LINETOKEN']
       msg=rows[row]
       print(token,msg,"-------------")
       
def login(sess: requests.Session):
    r = sess.post(
        'https://my.freenom.com/dologin.php',
        headers = {
            'Referer': 'https://my.freenom.com/clientarea.php',
        },
        data = {
            'username': os.environ['USERNAME'],
            'password': os.environ['PASSWORD'],
        })

    if 400 <= r.status_code < 600:
        logging.error('Login request failed')
        logging.error(r.content)
        r.raise_for_status()
    else:
        query = urllib.parse.urlparse(r.url).query
        if urllib.parse.parse_qs(query).get('incorrect') == 'true':
            logging.error('Login failed: incorrect details')
            sys.exit(1)


def list_domains(sess: requests.Session) -> list:
    # Domain List: name, status, remaining days, renewable message, renewable url
    uri = 'https://my.freenom.com/domains.php?a=renewals'
    r = sess.get(
        uri, headers = {
            'Referer': 'https://my.freenom.com/clientarea.php',
        })
    r.raise_for_status()

    html = bs4.BeautifulSoup(r.content, 'html.parser')
    domain_content = html('section', class_ = 'renewalContent')
    assert len(
        domain_content
    ) == 1, 'Domains page should only contain one renewalContent section'

    maxlen = 10
    titles = []
    rows = []
    for tr in domain_content[0]('tr'):
        if len(tr('th')) > 0:
            for th in tr('th'):
                text = trim(th.text)
                if text:
                    titles.append(text)
        else:
            is_domain = True
            rows.append([])
            for td in tr('td'):
                text = trim(td.text)
                if text == 'Renew This Domain':
                    assert len(
                        td('a')
                    ) == 1, 'More than one link found in Renew This Domain column'
                    rows[-1].append(
                        urllib.parse.urljoin(uri,
                                             td('a')[0]['href']))
                elif text:
                    rows[-1].append(text)
                    if is_domain:
                        maxlen = max(maxlen, len(text))
                        is_domain = False

    logging.info('Domain List:')
    logging_table(titles, rows, maxlen)
    return rows


def renew_domain(uri: str, sess: requests.Session, name: str = None):
    query = urllib.parse.urlparse(uri).query
    domain_id = urllib.parse.parse_qs(query).get('domain')
    if not domain_id:
        logging.error(f'Unable to get domain id from {uri}')
        return

    domain_id = domain_id[0]
    logging.debug(f'domain id "{domain_id}"')

    # Just get the page, not sure it is needed indeed or not.
    r = sess.get(
        uri,
        headers = {
            'Referer': 'https://my.freenom.com/domains.php?a=renewals',
        })

    r = sess.post(
        'https://my.freenom.com/domains.php?submitrenewals=true',
        headers = {
            'Referer': uri,
        },
        data = {
            'renewalid': domain_id,
            f'renewalperiod[{domain_id}]': os.environ.get('PERIOD', '12M'),
            'paymentmethod': 'credit',
        })
    logging.info(f'Response {r.status_code} {r.reason}')

    if not name:
        name = domain_id
    os.makedirs('result', exist_ok = True)
    with open(f'result/{name}.html', 'wb') as f:
        f.write(r.content)


def main():
    with requests.Session() as sess:
        sess.mount('http://', requests.adapters.HTTPAdapter(max_retries = 5))
        sess.mount('https://', requests.adapters.HTTPAdapter(max_retries = 5))

        login(sess)
        domains = list_domains(sess)

        renew = False
        for domain in domains:
            if 'Renewable' in domain[3] or int(
                    re.search(r'\d+', domain[2]).group()) <= 14:
                renew = True
                time.sleep(5)
                renew_domain(domain[-1], sess, domain[0])
        if not renew:
            logging.info('Nothing to renew')
            return

        domains = list_domains(sess)
        failed = False
        for domain in domains:
            if 'Renewable' in domain[3] or int(
                    re.search(r'\d+', domain[2]).group()) <= 10:
                logging.error(f'Renew failed with domain "{domain[0]}"')
                failed = True
        if failed:
            sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(
        level = logging.DEBUG,
        format = '%(asctime)s %(levelname)s %(message)s',
        datefmt = "%H:%M:%S")
    main()
