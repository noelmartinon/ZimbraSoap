#!/usr/bin/env python3
###############################################################################
# ZimbraSoap example - Export distribution lists members to json format       #
#                                                                             #
# Copyright (C) 2024  Noël MARTINON - noel.martinon@gmail.com                 #
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
    try:
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

        dls_json = zs.get_distribution_lists_export(config['domain'], config['dl_emails_prefix'], config['dl_emails_forwarder_tag'])
        print(json.dumps(dls_json, indent=2))

        # Export to file if required
        if 'dl_directory_export' in config and config['dl_directory_export']:
            dl_directory_export = config['dl_directory_export']

            # Create export directory
            Path(dl_directory_export).mkdir(parents=True, exist_ok=True)

            # Export each dl to separate files
            for dl_email in dls_json:
                prefix = dl_email.split('@')[0]
                with Path(dl_directory_export+'/'+prefix+'.txt').open('w') as txt_file:
                    for email in dls_json[dl_email]:
                        txt_file.write(email+'\n')
    except:
        return {}

if __name__ == '__main__':
    main()
