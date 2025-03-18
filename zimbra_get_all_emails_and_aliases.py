#!/usr/bin/env python3
###############################################################################
# ZimbraSoap example - Export distribution lists members to json format       #
#                                                                             #
# Copyright (C) 2025  Noël MARTINON - noel.martinon@gmail.com                 #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
###############################################################################

from pathlib import Path
from zimbrasoap import ZimbraSoap
import json


def main():
    config_file = 'zimbra_config.json'
    if not Path(config_file).is_file():
        config_file = 'inc/'+config_file

    with open(config_file, 'r') as jsonfile:
        config = json.load(jsonfile)

    try:
        # Init connection
        zs = ZimbraSoap(config['url'], config['admin_username'], config['admin_password'])
    except:
        print('Erreur impossible de se connecter au serveur Zimbra')
        exit(1)

    # dls_json = zs.get_distribution_lists_export(config['domain'], '', '')
    # print('############################')
    # print('#  Listes de distribution  #')
    # print('############################')
    # for key in dls_json.keys():
    #     print(key)

    dls_xml = zs.get_distribution_lists(config['domain'])
    dls = dls_xml['soap:Envelope']['soap:Body']["GetAllDistributionListsResponse"]['dl']
    print('############################')
    print('#  Listes de distribution  #')
    print('############################')
    for dl in dls:
        print(dl['@name'])
        for a in dl['a']:
            if a['@n']=='zimbraMailAlias' and a['#text']!=dl['@name']:
                print(' => ' + a['#text'])

    accounts_xml = zs.get_accounts(config['domain'])
    accounts = accounts_xml['soap:Envelope']['soap:Body']["GetAllAccountsResponse"]["account"]
    accounts = sorted(accounts, key=lambda x: x['@name'])
    print('############################')
    print('#  Adresses de messagerie  #')
    print('############################')
    for account in accounts:
        print(account['@name'])
        for a in account['a']:
            if a['@n']=='zimbraMailAlias':
                print(' => ' + a['#text'])

if __name__ == '__main__':
    main()
