#!/usr/bin/env python3
"""f2b_cf - a cli for interfacing fail2ban to cloudflare's ip lists

Copyright (c) 2025 Jose Kahan (W3C)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

"""
Sample usage:

#ban
f2b_cf -b 192.0.2.1
#unban
f2b_cf -u 192.0.2.1
#clear all bans
f2b_cf -c
# dump the contents of the ban list
f2b_cf -d
# use -p to select the permanent ban list (valid for all operations)
# ban using the permanent ban list
f2b_cf -b 192.0.2.1  -p
# give an alternate location for the configuration file
f2b_cf -f /path/to/config_file.txt

** This script assumes you

- have created an IP List (Account / Configurations / List)
   (e.g with name 'f2b_thelounge')
- have created a WAF custom ruleset, binded with the above ip list
  and with action block:
    "(ip.src in $f2b_thelounge)"
- have created an Account API Token (Manage Account / Account API Tokens /
    Create Custom Token) with 'Account Filter List permissions'
   (for security reasons, don't forget to configure its Client IP
    Address Filtering)

You'll need to create a configuration file giving all that info
to the script. See dot.env.dist.

Currently the script assumes that file is named .env and is
located in the same dir where the script is running.

Requires Python 3.x and Cloudflare's Python Library [1]

pip install dotenv
pip install cloudflare

[1] https://github.com/cloudflare/cloudflare-python/tree/main

"""

__author__ = "Jose Kahan (W3C)"
__copyright = "Copyright (c) 2025 Jose Kahan"
__license__ = "MIT"
__version__ = "1.0.0"

import os
import sys
import argparse
import ipaddress
from dotenv import dotenv_values

from cloudflare import Cloudflare, APIConnectionError, RateLimitError, APIStatusError
from cloudflare.types.rules.lists import (
    ItemGetResponse,
    ItemCreateResponse,
    ItemDeleteResponse,
    ItemUpdateResponse,
)
from cloudflare.types.rules.lists_list import (
    ListsList,
)

class Fail2BanCloudflareError(Exception):
    pass

def lists_info_get(client, account_id, list_id):
    "returns list info (doesn't return its items, just the list characteristics)"

    rv = client.rules.lists.get(account_id=account_id, list_id=list_id)
    if not rv or not isinstance(rv, ListsList):
        raise Fail2BanCloudflareError(f'error accessing list {list_id}')
    return rv

def list_items_list(client, account_id, list_id):
    "get list items (returns a list)"

    rv = client.rules.lists.items.list(account_id=account_id, list_id=list_id)
    if not rv or not rv.success:
        raise Fail2BanCloudflareError(f'error accessing list {list_id}')
    return rv

def list_items_print(items):
    for item in items:
        print (f"id: {item['id']}, ip: {item['ip']}")

def list_items_create(client, account_id, list_id, ip, comment="f2b_cf"):
    "add a list item (returns operation id, not the id of the created item)"

    ip = ipv6_cidr(ip)
    rv = client.rules.lists.items.create(account_id=account_id, list_id=list_id,
                                         body=[ {'ip' : ip,
                                                 'comment': comment}
                                               ])
    if not isinstance(rv, ItemCreateResponse):
        raise Fail2BanCloudflareError(f'error adding item {ip} to list {list_id}')
    return rv

def list_items_get_by_ip(client, account_id, list_id, ip):
    ip = ipv6_cidr(ip)
    items = list_items_list(client, account_id, list_id)
    for item in items:
        if item['ip'] == ip:
            return item['id']

def list_items_delete_by_id(client, account_id, list_id, item_id):
    "deletes an item with id 'item_id' from an IP list"

    rv = client.rules.lists.items.delete(account_id=account_id, list_id=list_id,
                                         extra_body={ 'items': [ {'id': item_id} ] })

    if not isinstance(rv, ItemDeleteResponse):
        raise Fail2BanCloudflareError(f'error deleting item {item_id} from list {list_id}')

    return rv

def list_items_delete_by_ip(client, account_id, list_id, ip):
    "deletes an item with ip 'ip' from an IP list"

    item_id = list_items_get_by_ip(client, account_id, list_id, ip)

    if not item_id:
        raise Fail2BanCloudflareError(f'error finding list item for ip {ip}')

    return list_items_delete_by_id(client, account_id, list_id, item_id)

def list_items_clear(client, account_id, list_id):
    rv = client.rules.lists.items.update(account_id=account_id, list_id=list_id,
                                         body=[])
    if not isinstance(rv, ItemUpdateResponse):
        raise Fail2BanCloudflareError(f'error clearing list {list_id}')

    return rv

def list_items_show(client, account_id, list_id):
    """Displays the ip list name, the number of items, and
    the ID and IP address of each item"""

    list_info = lists_info_get(client, account_id, list_id)
    assert list_info is not None
    print(f"list '{list_info.name}' has {list_info.num_items} items")
    if list_info.num_items == '0.0':
        return
    items = list_items_list(client, account_id, list_id)
    list_items_print(items)

def tests(client, account_id, list_id):
    """mostly checks that our use of the cloudflare API is still
    working and not deprecated"""

    test_ipv4 = '192.168.0.1'
    test_ipv6 = '2001:db8:85a3:8d3:1319:8a2e:370:7348'
    test_ipv6_cidr = '2001:db8:85a3:8d3::/64'

    print("testing ipv6_cidr reduction")
    test_ip = ipv6_cidr(test_ipv6)
    assert test_ip == test_ipv6_cidr
    test_ip = ipv6_cidr(test_ipv4)
    assert test_ip == test_ipv4

    print("state of the list before adding an item")
    list_info = lists_info_get(client, account_id, list_id)
    assert list_info is not None
    print(f"list '{list_info.name}' has {list_info.num_items} items")

    print("contents of the list before adding an item")
    items = list_items_list(client, account_id, list_id)
    assert items is not None
    assert items.success == True
    list_items_print(items)

    print(f"adding ip {test_ipv4}")
    list_items_create(client, account_id, list_id, test_ipv4, "f2b")

    print(f"checking that item was added")
    item_id = list_items_get_by_ip(client, account_id, list_id, test_ipv4)
    assert item_id is not None

    print(f"deleting item {item_id} : {test_ipv4}")
    list_items_delete_by_id(client, account_id, list_id, item_id)

    # check that the item doesn't exist
    item_id = list_items_get_by_ip(client, account_id, list_id, test_ipv4)
    assert item_id is None

    print("add three items to the list, then clear it")
    list_items_create(client, account_id, list_id, test_ipv4, 'sample ipv4')
    list_items_create(client, account_id, list_id, test_ipv6, 'sample ipv6')
    list_items_clear(client, account_id, list_id)
    items = list_items_list(client, account_id, list_id)
    assert len(items.result) == 0

    print("\nAll tests ran succesfully\n")

def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__.strip().splitlines()[0])
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        '-b', '--ban', type=str, metavar='ADDRESS',
        help='IP address to ban')
    action_group.add_argument(
        '-u', '--unban', type=str, metavar='ADDRESS',
        help='IP address to unban')
    action_group.add_argument(
        '-c', '--clear', action='store_true',
        help="clear CF's IP List")
    action_group.add_argument(
        '-d', '--dump', action='store_true',
        help="dumps the content of CF's IP List")
    action_group.add_argument(
        '-t', '--test', action='store_true',
        help="test the CF API (will clear your banned IP list entries, use with caution)")
    action_group.add_argument(
        '-p', '--permanent-ban', action='store_true',
        help='use the permanent ban IP List')
    action_group.add_argument(
        '-v', '--version', action='store_true',
        help=f"prints f2b_cf version number")
    parser.add_argument(
        '-f', '--config-file', type=str, default='.env',
        help="path pointing to a config file (default '.env'")

    return parser.parse_args()

def read_config(config_file='.env'):

    config = {
        **dotenv_values(config_file),  # load shared development variables
        #**os.environ,  # override loaded values with environment variables
    }
    return config

def ipv6_cidr(ip_address):
    ipa = ipaddress.ip_address(ip_address)
    if ipa.version == 4:
        rv = ip_address
    else:
        rv = ipaddress.ip_network(ipa).supernet(new_prefix=64)
        rv = str(rv)

    return rv

def main():

    args = parse_args()
    if args.version:
        print(f"f2b_cf v{__version__}")
        sys.exit(0)

    config = read_config(args.config_file)

    if not config:
        print(f"{args.config_file} configuration file is empty / non-existent",
              file=sys.stderr)
        return -1

    account_id = config['CLOUDFLARE_ACCOUNT_ID']
    if args.permanent_ban:
        list_id = config['CLOUDFLARE_F2B_PERMANENT_IP_LIST']
    else:
        list_id = config['CLOUDFLARE_F2B_IP_LIST']

    client = Cloudflare(
        # This is the default and can be omitted
        api_token=config["CLOUDFLARE_API_TOKEN"],
    )

    if args.test:
        command = tests
        command_args = [client, account_id, list_id]

    elif args.ban:
        command = list_items_create
        command_args = [client, account_id, list_id, args.ban]

    elif args.unban:
        command = list_items_delete_by_ip
        command_args = [client, account_id, list_id, args.unban]

    elif args.clear:
        command = list_items_clear
        command_args = [client, account_id, list_id]

    elif args.dump:
        command = list_items_show
        command_args = [client, account_id, list_id]

    try:
        command(*command_args)
    except APIConnectionError as e:
        print("The server could not be reached", file=sys.stderr)
        print(e.__cause__)  # an underlying Exception, likely raised within httpx.
        return -1
    except RateLimitError as e:
        print("A 429 status code was received; we should back off a bit.",
              file=sys.stderr)
        return -1
    except APIStatusError as e:
        print("Another non-200-range status code was received", file=sys.stderr)
        print(f"Received a {e.status_code} status_code", file=sys.stderr)
        for error in e.errors:
            print (f"Error message: {error.message}", file=sys.stderr)
        return -1
    except Fail2BanCloudflareError as e:
        print(e, file=sys.stderr)
        return -1

    return 0

if __name__ == '__main__':
    sys.exit(main())  # next section explains the use of sys.exit
