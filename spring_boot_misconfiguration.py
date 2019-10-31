#!/usr/bin/env python3

from colorama import Fore, init
from functools import partial
from multiprocessing import Pool
import argparse
import requests
import sys


init(autoreset=True) # to reset colorama color style.

def fetch_spring(output_f, url, endpoints):
    """
    This function will tell us about vulnerable domains
    :param output_f: name of the output file
    :param url: url name
    :param endpoints: list of endpoints
    """
    endpoint = endpoints.strip()

    # checking if there is empty string in domain or new line at the end.
    if endpoint == "":
        return

    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + endpoint

    if not url.endswith('/'):
        url += endpoint
    else:
        url += endpoint

    try:
        # Testing if url is valid or not
        response = requests.get(url, timeout=5)
        response_value = response.status_code
    except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as err:
        print(Fore.RED + url)
        return

    if response_value != 200:
        print(Fore.RED + url)
        return

    print(Fore.GREEN + url)

    # Writing final output to the file
    try:
        with open(output_f, 'a') as f:
            f.write(''.join([url, '\n']))
    except Exception as e:
        print(Fore.RED + e)




def read_file(filename):
    """
    It will read the file and return the content.
    :param filename: name of the file
    """
    with open(filename) as f:
        return f.readlines()


def main():
    print("""
    It will look for the domains which are vulnerable to spring boot misconfiguration.
    """)

    # Argument Parsing
    parser = argparse.ArgumentParser(usage='%(prog)s -u url [-o output_file]')
    parser.add_argument('-u', '--url', default='google.com', help='url')
    parser.add_argument('-o', '--outputfile', default='output.txt', help='output file')
    parser.add_argument('-t', '--threads', default=20, help='threads')
    args = parser.parse_args()

    url = args.url
    output_f = args.outputfile
    try:
        max_processes = int(args.threads)
    except ValueError as err:
        sys.exit(err)

    endpoints = ['actuator', 'auditevents', 'autoconfig', 'beans', 'configprops', 'dump', 'env', 'flyway', 'health', 'info', 'loggers', 'liquibase', 'metrics', 'mappings', 'shutdown', 'trace', 'heapdump', 'jolokia', 'logfile'] # endpoints to check
    fun = partial(fetch_spring, output_f, url)
    with Pool(processes=max_processes) as pool:
        pool.map(fun, endpoints)
    print('Finished')


if __name__ == '__main__':
    main()
