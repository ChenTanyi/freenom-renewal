#!/usr/bin/env python3
import os
import sys
import json
import requests
import logging
import urllib.parse


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
        query = urllib.parse.urlparse(r.url)
        if urllib.parse.parse_qs(query).get('incorrect') == 'true':
            logging.error('Login failed: incorrect details')
            sys.exit(1)


def main():
    with requests.Session() as sess:
        login(sess)


if __name__ == "__main__":
    logging.basicConfig(
        level = logging.DEBUG,
        format = '%(asctime)s %(levelname)s %(message)s',
        datefmt = "%H:%M:%S")
    main()