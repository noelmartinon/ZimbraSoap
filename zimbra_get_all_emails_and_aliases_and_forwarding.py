#!/usr/bin/env python3
###############################################################################
# ZimbraSoap example - Export distribution lists aliases and accounts         #
#                      emails,alias,emails_forwarding in csv format           #
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

    dls_xml = zs.get_distribution_lists(config['domain'])
    dls = dls_xml['soap:Envelope']['soap:Body']["GetAllDistributionListsResponse"]['dl']
    print('############################')
    print('#  Listes de distribution  #')
    print('############################')
    print('email,alias')
    csv_dl = open('distribution_lists.csv', 'w', encoding='UTF8')
    csv_dl.write('email,alias\n')
    for dl in dls:
        aliases = []
        for a in dl['a']:
            if a['@n']=='zimbraMailAlias' and a['#text']!=dl['@name']:
                aliases.append(a['#text'])
        print('{},{}'.format(dl['@name'], ' '.join(aliases)))
        csv_dl.write('{},{}'.format(dl['@name'], ' '.join(aliases)))
        csv_dl.write('\n')
    csv_dl.close()


    accounts_xml = zs.get_accounts(config['domain'])
    accounts = accounts_xml['soap:Envelope']['soap:Body']["GetAllAccountsResponse"]["account"]
    accounts = sorted(accounts, key=lambda x: x['@name'])
    print('\n')
    print('############################')
    print('#  Adresses de messagerie  #')
    print('############################')
    print('email,alias,redirection')
    csv_accounts = open('accounts.csv', 'w', encoding='UTF8')
    csv_accounts.write('email,alias\n')
    for account in accounts:
        aliases = []
        fwd_addresses = []
        for a in account['a']:
            if a['@n']=='zimbraMailAlias':
                aliases.append(a['#text'])
            elif a['@n']=='zimbraPrefMailForwardingAddress':
                fwd_addresses_array = a['#text'].split(',')
                for fwda in fwd_addresses_array:
                    fwd_addresses.append(fwda)
        print('{},{},{}'.format(account['@name'], ' '.join(aliases), ' '.join(fwd_addresses)))
        csv_accounts.write('{},{},{}'.format(account['@name'], ' '.join(aliases), ' '.join(fwd_addresses)))
        csv_accounts.write('\n')
    csv_accounts.close()

        # Get ForwardingAddress:
        # fwdAddress = zs.get_prefs(dl['@name'], ['zimbraPrefMailForwardingAddress'])
        # if fwdAddress:
        #     for k, v in zs.get_prefs(dl['@name'], ['zimbraPrefMailForwardingAddress']).items():
        #         if k == 'zimbraPrefMailForwardingAddress':
        #             print('REDIR->', v)

if __name__ == '__main__':
    main()
