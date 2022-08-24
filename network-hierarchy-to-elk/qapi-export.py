#!/bin/python
# qapi-export
# version: 3.7.1
# author: Dmytro Petrashchuk
# email: dpgbox@gmail.com
# Script to export/import data through IBM QRadar API
#
# Prerequisites for script
# 1. Install Python 3.6.5 or later
# 2. Add requests, tabulate modules:
#       >   pip install requests tabulate
# 3. Create the configuration file with the same name and .conf extention
# 4. Use command line parameters or configuration file:
#       QRADAR_IP = IBM QRadar SIEM server
#       TOKEN = Security token for communicating with IBM QRadar SIEM server
# 5. See the inline help with -h
#
# DONE: Add Delete operation for reftable objects
# DONE: Add TAB separator to CSV
# DONE: Added RefTables and RefTable objects
#
# TODO: Modify filter and fields functionality to be able to operate on incapsulated json parameters
# TODO: Add Logsources operations
# TODO: Add operation "count"
# TODO: Add LSGroups operations
# TODO: Add RefSets, RefMaps, RefMapSets operations. For them add Ref:_name_ notations as well
# TODO: Add AQL requests from command line
# TODO: Add saving the last API request and all the data and restoring from lost position
# TODO: Add Module wrapper for all options
#
import argparse
import csv
import json
import logging
import requests
import socket
import configparser
import sys
import datetime
import time
from urllib.parse import quote
import re
from tabulate import tabulate
from http.client import responses

# Ignore SSL-warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Base constants and paths
BASE_URI = '/api/'
SCRIPT_NAME = sys.argv[0].split('.')[0]
CONFIG_NAME = SCRIPT_NAME + '.conf'
LOG_NAME = SCRIPT_NAME + '.log'

# Endpoint object
endpoints = [{
    'object': 'networks',
    'method': 'export',
    'endpoint': 'config/network_hierarchy/networks',
    'fields': ['id', 'name', 'cidr', 'country_code', 'description', 'group', 'coord_x', 'coord_y', 'vlan', 'critical', 'wireless', 'address'],
    'filter_fields': ['id', 'name', 'cidr', 'country_code', 'description', 'group']
},
    {
    'object': 'assets',
    'method': 'export',
    'endpoint': 'asset_model/assets',
    'fields': ['id', 'IP'],
    'filter_fields': ['id', 'IP']
},
    {
    'object': 'networks',
    'method': 'import',
    'endpoint': 'config/network_hierarchy/staged_networks',
    'fields': ['id', 'name', 'cidr', 'country_code', 'description', 'group', 'coord_x', 'coord_y', 'vlan', 'critical', 'wireless', 'address'],
    'id':'id',
    'http': 'PUT'
},
    {
    'object': 'assets',
    'method': 'import',
    'endpoint': 'asset_model/assets/{id}',
    'fields': ['id'],
    'id':'id',
    'http': 'POST'
},
    {
    'object': 'reftables',
    'method': 'export',
    'endpoint': 'reference_data/tables',
    'fields': ['name', 'type', 'elements'],
    'http': 'GET'
},
    {
    'object': 'refsets',
    'method': 'export',
    'endpoint': 'reference_data/sets',
    'fields': ['name', 'type', 'elements'],
    'http': 'GET'
},
    {
    'object': 'refmaps',
    'method': 'export',
    'endpoint': 'reference_data/maps',
    'fields': ['name', 'type', 'elements'],
    'http': 'GET'
},
    {
    'object': 'refmapsets',
    'method': 'export',
    'endpoint': 'reference_data/map_of_sets',
    'fields': ['name', 'type', 'elements'],
    'http': 'GET'
},
    {
    'object': 'reftable',
    'method': 'export',
    'endpoint': 'reference_data/tables/{id}',
    'fields': ['name', 'type', 'elements'],
    'id': 'name',
    'http': 'GET'
},
    {
    'object': 'reftable',
    'method': 'import',
    'endpoint': 'reference_data/tables/bulk_load/{id}',
    'fields': ['name', 'type', 'elements'],
    'id': 'name',
    'http': 'POST'
},
    {
    'object': 'reftable',
    'method': 'delete',
    'endpoint': 'reference_data/tables/{id}/{key}/{field}?value={value}',
    'fields': ['name', 'type', 'elements'],
    'id': 'name',
    'http': 'DELETE'
},
    {
    'object': 'events',
    'method': 'export',
    'endpoint': 'ariel/searches',
    'fields': [],
    'http': 'GET'
}]

asset_property_names = []


def not_implemented(logger):
    error(logger, 'Function is not yet implemented! Try something else.')


def error(logger, message):
    logger.error('ERROR: ' + message)
    exit(1)


class RestApiClient:
    def __init__(self, qradar_ip, token, endpoint, logger, filter='', fields='', records='', refname='', dateformat='%Y-%m-%d %H:%M:%S', rowbyrow=False, aql=''):
        """Initialize the object for peroforming requests to QRadar API,
        storing and processing results."""
        # Setup logger
        self.logger = logger

        self.dateformat = dateformat
        self.rowbyrow = rowbyrow

        # Setup method
        if (endpoint['method'] == 'export'):
            self.method = 'GET'
        elif (endpoint['method'] in ['import', 'delete']):
            self.method = endpoint['http']
        else:
            not_implemented(logger)

        # Setup headers
        if endpoint['object'] == 'assets' and self.method == 'POST':
            self.headers = {b'Accept': 'text/plain'}
        else:
            self.headers = {b'Accept': 'application/json'}
        self.headers['Version'] = '11.0'  # Change this if API version updates
        if self.method == 'DELETE':
            self.headers['Content-Type'] = 'application/json'
        else:
            self.headers['Content-Type'] = 'application/json;charset=UTF-8'
        # If in Records only one number is set then convert it to range
        if records:
            if records.find('-') == -1:
                records = '0-'+str(int(records)-1)
            self.headers['Range'] = 'items='+records
        # Setup authentication header
        self.auth = {'SEC': token}
        self.headers.update(self.auth)
        # Setup connection variables
        self.server_ip = qradar_ip
        self.base_uri = BASE_URI
        self.endpoint = endpoint['endpoint']
        if aql and endpoint['object'] == 'events':
            self.aql = aql
        self.refname = refname
        # For assets read the list of porpertis and store in corresponding lists
        self.fields = endpoint['fields']
        self.date_fields = []
        if endpoint['object'] == 'assets':
            self.asset_properties = []
            self.asset_properties = self.get_asset_properties()
            for property in self.asset_properties:
                asset_property_names.append(property['name'])
            self.logger.debug(
                'Read following asset properties:{}'.format(asset_property_names))
            self.fields = endpoint.get('fields')
            self.fields.extend(asset_property_names)

        if endpoint['object'] in ['reftable']:
            if endpoint['method'] != 'delete':
                self.endpoint = self.endpoint.format(id=refname)
            else:
                self.endpoint = self.endpoint.format(
                    id=refname, key='{key}', field='{field}', value='{value}')
            ref_fields = []
            ref_fields = self.get_ref_fields(refname)
            self.fields = []
            self.fields.append(ref_fields[0].get('key_label'))
            self.fields.extend(ref_fields[0].get('key_name_types').keys())
            for field in ref_fields[0].get('key_name_types').keys():
                if ref_fields[0].get('key_name_types').get(field) == 'DATE':
                    self.date_fields.extend([field])

        if filter or fields:
            self.endpoint += '?'
            if filter and fields:
                self.endpoint += 'filter=' + \
                    quote(filter.encode())+'&fields='+quote(fields.encode())
            elif filter:
                self.endpoint += 'filter='+quote(filter.encode())
            elif fields:
                self.endpoint += 'fields='+quote(fields.encode())
        if fields:
            self.fields = list(
                set(endpoint['filter_fields']) & set(fields.split(',')))

        self.session = requests.session()
        self.response = None
        self.result = u''
        self.dict = []
        logger.debug('RestAPIClient initialized:')
        logger.debug(self)

    def __str__(self):
        return('IP:{}, AUTH:{}, ENDPOINT:{}, METHOD:{}, FIELDS:{}'.format(self.server_ip, self.auth, self.endpoint, self.method, self.fields))

    def call_api(self, endpoint=None, method=None, headers=None, data=None):
        if not endpoint:
            endpoint = self.endpoint
        if not method:
            method = self.method

        full_uri = 'https://' + self.server_ip + self.base_uri + endpoint

        if not headers:
            headers = self.headers
        else:
            for key, value in self.headers.items():
                if headers.get(key, '') == '':
                    headers[key] = value

        self.logger.debug('Sending ' + method +
                          ' request to: ' + full_uri)
        self.logger.debug(self.headers)
        if method == 'GET':
            try:
                self.response = self.session.get(
                    full_uri, headers=headers, verify=False)
                self.logger.debug('Server answer: ' +
                                  str(self.response.status_code)+' : '+responses[self.response.status_code])
                if self.response.status_code != requests.codes.ok:
                    self.response.raise_for_status()
                else:
                    self.result = self.response.text
                    if not self.result:
                        self.logger.error('Result is empty')
                        exit(1)
                return self.result
            except requests.exceptions.HTTPError as e:
                self.logger.error(e)
                exit(1)
                return e

        elif method == 'POST':
            try:
                self.logger.debug('-----POST Data:\n' + str(data))
                self.response = self.session.post(
                    full_uri, headers=headers, verify=False, data=data.encode('utf-8'))
                self.logger.debug('Server answer: ' +
                                  str(self.response.status_code)+' : '+responses[self.response.status_code])
                if self.response.status_code != requests.codes.ok:
                    self.response.raise_for_status()
                self.result = self.response.text
                return self.result
            except requests.exceptions.HTTPError as e:
                self.logger.error(e)
                exit(1)
                return e

        elif method == 'PUT':
            try:
                self.logger.debug('-----PUT Data:\n' + str(data))
                with open('data.json', mode='w', encoding='utf-8') as file:
                    file.write(str(data))
                self.response = requests.put(
                    full_uri, headers=headers, verify=False, data=data.encode('utf-8'))
                self.logger.debug('Server answer: ' +
                                  str(self.response.status_code)+' : '+responses[self.response.status_code])
                if self.response.status_code != requests.codes.ok:
                    self.response.raise_for_status()
                self.result = self.response.text
                return self.result
            except requests.exceptions.HTTPError as e:
                self.logger.error(e)
                exit(1)
                return e
        elif method == 'DELETE':
            try:
                self.response = requests.delete(
                    full_uri, headers=headers, verify=False)
                self.logger.debug('Server answer: ' +
                                  str(self.response.status_code)+' : '+responses[self.response.status_code])
                if self.response.status_code != requests.codes.ok:
                    self.response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                self.logger.error(e)
                exit(1)
                return e

    def write_api(self, endpoint):
        if self.method == 'POST':
            if endpoint.get('object') == 'assets':
                for row in self.dict:
                    id = row.get(endpoint['id'])
                    row.pop(endpoint['id'])
                    data = json.dumps(row, ensure_ascii=False)
                    endpoint_item = self.endpoint.format(id=id)
                    self.logger.debug('Writing POST data to ' + endpoint_item)
                    self.call_api(endpoint=endpoint_item, data=data)
            elif endpoint.get('object') in ['reftable', 'refmap', 'refset', 'refmapset']:
                if self.rowbyrow:
                    for row in self.dict:
                        data = json.dumps(row)
                        self.call_api(data=data)
                else:
                    data = {}
                    for row in self.dict:
                        data.update(row)
                    data = json.dumps(data)
                    self.call_api(data=data)
            else:
                not_implemented(self.logger)
        elif self.method == 'PUT':
            data = json.dumps(self.dict, ensure_ascii=False)
            self.call_api(data=data)
        else:
            not_implemented(self.logger)

    def delete(self, endpoint):
        if self.method == 'DELETE':
            if endpoint.get('object') == 'reftable':
                export_endpoint = {}
                for item in endpoints:
                    if item['object'] == endpoint['object'] and item['method'] == 'export':
                        export_endpoint = item
                if not export_endpoint:
                    not_implemented(self.logger)
                self.call_api(endpoint=export_endpoint['endpoint'].format(
                    id=self.refname), method=export_endpoint['http'])
                data = json.loads(self.result).get('data')
                for row in self.dict:
                    key = next(iter(row))
                    for item in data.get(key):
                        field = item
                        value = data.get(key).get(item).get('value')
                        self.call_api(endpoint=quote(endpoint['endpoint'].format(
                            id=self.refname, key=quote(key,safe='/*()'), field=quote(field,safe='/*()'), value=quote(value,safe='/*()'))))
            else:
                not_implemented(self.logger)
        else:
            not_implemented(self.logger)

    def save_json(self, filename):
        if self.result:
            json_text = json.loads(self.result)
            if filename:
                # Writing JSON data
                try:
                    with open(filename, mode='w', encoding='utf-8') as f:
                        json.dump(json_text, f, ensure_ascii=False)
                        f.close()
                        self.logger.debug('Json data saved {} objects in the {}'.format(
                            len(json.loads(self.result)), filename))
                except IOError as e:
                    self.logger.error(
                        'Cannot write the JSON into file: {}'.format(e))
        else:
            self.logger.error('No data for export')
            exit(1)

    def load_json(self, filename):
        with open(filename, mode='r', encoding='utf-8') as json_file:
            try:
                self.dict = json.load(json_file)
                self.result = json.dumps(self.dict, ensure_ascii=False)
                self.logger.debug('{} objects loaded from file {}'.format(
                    len(self.dict), filename))
            except ValueError as e:
                self.logger.error('Invalid json: {}'.format(e))
        json_file.close()
        return self.result

    def save_csv(self, filename, separator=','):
        if self.dict:
            # print(self.dict)
            # Open CSV-file to export data
            try:
                with open(filename, 'w', encoding='utf-8', newline='') as csvfile:
                    writer = csv.DictWriter(
                        csvfile, fieldnames=self.dict[0].keys(), restval='', extrasaction='ignore', delimiter=separator)
                    writer.writeheader()
                    for data in self.dict:
                        # print(data)
                        writer.writerow(data)
                    csvfile.close()
                    self.logger.debug('{} lines saved to CSV file {}'.format(
                        len(self.dict), filename))
            except IOError:
                self.logger.error('Cannot write the CSV into file')
        else:
            self.logger.error('No data for export')
            exit(1)

    def load_csv(self, filename, separator=','):
        with open(filename, mode='r', encoding='utf-8', newline='') as csv_file:
            try:
                self.dict.clear()
                csvdata = csv.DictReader(csv_file, delimiter=separator)
                for row in csvdata:
                    self.dict.append(dict(row))
                self.logger.debug('{} lines loaded from CSV file {}'.format(
                    len(self.dict), filename))
            except ValueError as e:
                self.logger.error('Invalid csv: {}'.format(e))
        csv_file.close()
        return self.dict

    def parse_inline(self, data):
        row = {}
        for param in data.split(','):
            pair = param.split('=')
            row.update({pair[0].strip(): pair[1].strip()})
        self.dict = [row]
        return self.dict

    def show(self):
        if self.dict:
            self.logger.debug('Trying to print data on screen')
            return tabulate(self.dict, headers='keys', tablefmt='github')
        else:
            self.logger.error('No data for printing')
            exit(1)

    def parse_json(self, endpoint):
        if self.result:
            self.dict.clear()
            self.dict=[]
            try:
                if endpoint in ['reftable', 'refmap', 'refset', 'refmapset']:
                    full_list = json.loads(self.result).get('data')
                elif  endpoint == 'events':
                    full_list = json.loads(self.result).get('events')
                else:
                    full_list = json.loads(self.result)
                for item in full_list:
                    item_dict = {}
                    if endpoint == 'networks':
                        if 'id' in self.fields:
                            item_dict.update({'id': item.get('id')})
                        if 'name' in self.fields:
                            item_dict.update({'name': item.get('name')})
                        if 'cidr' in self.fields:
                            item_dict.update({'cidr': item.get('cidr')})
                        if 'country_code' in self.fields:
                            item_dict.update(
                                {'country_code': item.get('country_code')})
                        if 'group' in self.fields:
                            item_dict.update({'group': item.get('group')})
                        if ('coord_x' in self.fields) or ('coord_y' in self.fields):
                            coord = item.get('location')
                            if coord:
                                coord = coord.get('coordinates')
                                if coord:
                                    x = coord[0]
                                    y = coord[1]
                                else:
                                    x = y = 0
                            else:
                                x = y = 0
                            if 'coord_x' in self.fields:
                                item_dict.update({'coord_x': x})
                            if 'coord_y' in self.fields:
                                item_dict.update({'coord_y': y})
                        if 'description' in self.fields:
                            item_dict.update(
                                {'description': item.get('description')})
                            desc = re.compile(
                                r"^(?P<vlan>\<\d+\>)?\s*(?P<crit>\[Critical VLAN\])?\s*(?P<wf>\[Wireless\])?\s*(?P<address>.*)$")
                            m = desc.match(item.get('description'))
                            if m:
                                vlan = m.group('vlan')
                                vlan = vlan[1:-1] if vlan else ''
                                crit = 1 if m.group('crit') else 0
                                wf = 1 if m.group('wf') else 0
                                address = m.group('address')
                            else:
                                vlan = address = ''
                                crit = wf = 0
                            if 'vlan' in self.fields:
                                item_dict.update({'vlan': vlan})
                            if 'critical' in self.fields:
                                item_dict.update({'critical': crit})
                            if 'wireless' in self.fields:
                                item_dict.update({'wireless': wf})
                            if 'address' in self.fields:
                                item_dict.update({'address': address})
                    elif endpoint == 'assets':
                        if 'id' in self.fields:
                            item_dict.update({'id': item.get('id')})
                        if 'IP' in self.fields:
                            ips = self.getips(item.get('interfaces'))
                            ip = 'none'
                            if ips:
                                ip = ips[0]
                            item_dict.update({'IP': ip})
                        properties = item.get('properties')
                        for property in properties:
                            if property['name'] in self.fields:
                                item_dict.update(
                                    {property['name']: property['value']})
                    elif endpoint in ['reftables', 'refmaps', 'refsets', 'refmapsets']:
                        if 'name' in self.fields:
                            item_dict.update({'name': item.get('name')})
                        if 'type' in self.fields:
                            item_dict.update(
                                {'type': item.get('element_type')})
                        if 'elements' in self.fields:
                            item_dict.update(
                                {'elements': item.get('number_of_elements')})
                    elif endpoint in ['reftable', 'refmap', 'refset', 'refmapset']:
                        for field in self.fields:
                            if field == self.fields[0]:
                                item_dict.update({field: item})
                            else:
                                content = full_list.get(item)
                                value = ''
                                if content:
                                    content = content.get(field)
                                    if content:
                                        content = content.get('value')
                                        if content:
                                            value = content
                                if value and field in self.date_fields:
                                    value = datetime.datetime.fromtimestamp(
                                        int(value)/1000).strftime(self.dateformat)
                                item_dict.update({field: value})
                    elif endpoint=='events':
                        item_dict.update(item)
                    else:
                        not_implemented(self.logger)
                    self.dict.append(item_dict)
                self.logger.debug(
                    'JSON parser successfully processed {} lines'.format(len(self.dict)))
            except Exception as e:
                self.logger.error(
                    'Cannot read content of the table! ({})'.format(e))
        else:
            self.logger.error('No data for export')
            exit(1)
        return self.dict

    def jsonify(self, endpoint):
        if self.dict:
            self.result = ''
            jsoned = []
            for item in self.dict:
                item_json = {}
                if endpoint == 'networks':
                    item_json.update({'id': int(item.get('id'))})
                    item_json.update({'name': item.get('name')})
                    item_json.update({'cidr': item.get('cidr')})
                    if item.get('country_code') != '':
                        item_json.update(
                            {'country_code': item.get('country_code')})
                    item_json.update({'group': item.get('group')})
                    if (item.get('coord_x') != '0')and(item.get('coord_y') != '0'):
                        item_json.update({'location': {'coordinates': [float(
                            item.get('coord_x')), float(item.get('coord_y'))], 'type': 'Point'}})
                    if item.get('description') != '':
                        description = item.get('description')
                    vlan = item.get('vlan')
                    critical = int(item.get('critical'))
                    wireless = int(item.get('wireless'))
                    address = item.get('address')
                    if not description and (vlan or critical or wireless or address):
                        description = ''
                        if vlan:
                            description = '<'+str(vlan)+'>'
                        if critical == 1:
                            description += '[Critical VLAN]'
                        if wireless == 1:
                            description += '[Wireless]'
                        description += address
                    item_json.update({'description': description})
                elif endpoint == 'assets':
                    item_json.update({'id': item.get('id')})
                    properties = []
                    for property in self.asset_properties:
                        if (property['name'] in item.keys()) and (item.get(property['name']) != ''):
                            properties.append(
                                {'type_id': property['id'], 'value': item.get(property['name'])})
                    item_json.update({'properties': properties})
                elif endpoint in ['reftable', 'refmap', 'refset', 'refmapset']:
                    temp_json = {}
                    key = item.pop(self.fields[0])
                    for field in item.keys():
                        value = item.get(field)
                        if field in['Average window','Average MB rate']:
                            value= value.replace(",",".")
                        if value and value != '':
                            if field in self.date_fields:
                                value = '{:.0f}'.format(datetime.datetime.timestamp(
                                    datetime.datetime.strptime(value, self.dateformat))*1000)
                            temp_json.update({field: value})
                    item_json.update({key: temp_json})
                else:
                    not_implemented(self.logger)
                jsoned.append(item_json)
            self.dict = jsoned
            self.result = json.dumps(jsoned, ensure_ascii=False)
            self.logger.debug(
                '{} object(s) parsed from input'.format(len(self.dict)))
        else:
            self.logger.error('No data for import')
            exit(1)
        return self.dict

    def getips(self, interfaces):
        ips = []
        for interface in interfaces:
            if 'ip_addresses' in interface.keys():
                for ip in interface.get('ip_addresses'):
                    if (ip['value'][0:2] != '127') and (ip['value'][0] != ':'):
                        ips.append(ip['value'])
        return ips

    def get_asset_properties(self):
        full_uri = 'https://' + self.server_ip + self.base_uri + \
            'asset_model/properties?fields=id%2C%20name'
        headers = {b'Accept': 'application/json'}
        headers['Version'] = '9.1'
        headers['Content-Type'] = 'application/json'
        headers.update(self.auth)
        self.logger.debug('Sending GET request to: ' + full_uri)
        try:
            response = requests.get(full_uri, headers=headers, verify=False)
            self.logger.debug('Server answer: ' +
                              str(response.status_code))
            if response.status_code != requests.codes.ok:
                response.raise_for_status()
            else:
                result = response.text.encode('utf-8')
                return json.loads(result)
        except requests.exceptions.HTTPError as e:
            self.logger.error(e)
            return e

    def get_ref_fields(self, refname):
        full_uri = 'https://' + self.server_ip + self.base_uri + \
            'reference_data/tables?filter=name%3D%22'+quote(refname)+'%22'
        headers = {b'Accept': 'application/json'}
        headers['Version'] = '9.1'
        headers['Content-Type'] = 'application/json'
        headers.update(self.auth)
        self.logger.debug('Sending GET request to: ' + full_uri)
        try:
            response = requests.get(full_uri, headers=headers, verify=False)
            self.logger.debug('Server answer: ' +
                              str(response.status_code))
            if response.status_code != requests.codes.ok:
                response.raise_for_status()
            else:
                result = response.text.encode('utf-8')
                return json.loads(result)
        except requests.exceptions.HTTPError as e:
            self.logger.error(e)
            return e

    def prepare_aql(self, endpoint):
        if self.aql:
            if self.aql[0:6].lower() == 'select'[:]:
                url = endpoint['endpoint']+'?query_expression='+self.aql
            elif self.aql[0:2].lower() == 'id'[:]:
                url = endpoint['endpoint']+'?saved_search_id='+self.aql[3:]
            else:
                config = configparser.ConfigParser()
                try:
                    config.read(CONFIG_NAME)
                    self.logger.debug('Treing to read AQL from ' + CONFIG_NAME)
                    self.aql = config['AQLS'][self.aql]
                    self.logger.debug('Read AQL from config: ' + self.aql)
                    url = endpoint['endpoint']+'?query_expression='+self.aql
                except:
                    error(self.logger, 'Configuration file "'+CONFIG_NAME +
                          '" is not found, have wrong format, section [AQLS] is missing or AQL "'+self.aql+'" is not found')
            self.call_api(endpoint=url, method='POST', data='')
            answer = json.loads(self.result)
            search_id = answer.get('search_id')
            self.logger.debug('Search ID = '+search_id)
            progress = 0
            result = ''
            url = endpoint['endpoint']+'/'+search_id
            while not result in ['COMPLETED', 'CANCELED', 'ERROR']:
                self.call_api(endpoint=url)
                answer = json.loads(self.result)
                progress = answer.get('progress')
                result = answer.get('status')
                self.logger.info("Progress - {}%".format(progress))
                time.sleep(1)
            exectime = answer.get('query_execution_time')
            self.logger.info("Search completed. Execution time {0:.2f} seconds".format(int(exectime)/1000))
            self.endpoint = endpoint['endpoint']+'/'+search_id+'/results'
            return self.endpoint
        else:
            self.logger.error('Wrong AQL request')
            exit(1)


def main():
    # Parse the comand line first
    parser = argparse.ArgumentParser(
        description='Connect to QRadar API and manipulate the data')
    parser.add_argument('operation', help='export, import, delete, fields')
    parser.add_argument(
        'objects', help='what to manipulate: assets, networks, reftables, refmaps, refsets, refmapsets, reftable, events')
    parser.add_argument(
        '--filter',
        dest='filter',
        help='Filter to apply to results')
    parser.add_argument(
        '--fields',
        dest='fields',
        help='List of fields to export (no sense for import)')
    parser.add_argument(
        '--records',
        dest='records',
        help='Number of records to export (no sense for import)')
    parser.add_argument(
        '--config',
        dest='config_section',
        help='Configuration section in ' + CONFIG_NAME + ' with QRADAR_IP/TOKEN parameters')
    parser.add_argument(
        '--host', dest='qradar_ip',
        help='IP Address of QRadar Appliance')
    parser.add_argument(
        '--token', dest='token',
        help='SEC Token')
    parser.add_argument('--csv', dest='csv_filename',
                        help='CSV file you would like to import/export')
    parser.add_argument('--json', dest='json_filename',
                        help='JSON file you would like to import/export')
    parser.add_argument('--data', dest='values',
                        help='Values to save into object in format "field1=value1,field2=value2". Do not forget to place "id" first!')
    parser.add_argument('--name', dest='refname',
                        help='Name of reference object to work with')
    parser.add_argument('--aql', dest='aql',
                        help='AQL request to get data for Ariel DB')
    parser.add_argument('--dateformat', dest='dateformat',
                        help='Format of the date values in python strftime notation. Default - %%Y-%%m-%%d %%H:%%M:%%S',
                        default='%Y-%m-%d %H:%M:%S')
    parser.add_argument('--screen', dest='screen', action='store_true',
                        help='Print on screen')
    parser.add_argument('-d', dest='debug', action='store_true',
                        help='Use to turn Debug mode on')
    parser.add_argument('-v', dest='verbose',
                        action='store_true', help='print log to stdout')
    parser.add_argument('-t', dest='tab',
                        action='store_true', help='use <TAB> as separator in CSV')
    parser.add_argument('-r', dest='rowbyrow',
                        action='store_true', help='update bulk data row by row instead of single operation')
    args = parser.parse_args()

    # Initialize logging
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=logging.DEBUG, filename=LOG_NAME)
    logger = logging.getLogger(SCRIPT_NAME)
    if args.verbose:
        logger.addHandler(logging.StreamHandler())

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.info('====== Script run: ' + str(sys.argv))

    # Check for errors in arguments
    # 1) no config or host+token
    if not (args.config_section or args.qradar_ip or args.token):
        error(logger, 'Connection data is missing')
    # 2) both config and host or token
    if args.config_section and (args.qradar_ip or args.token):
        error(logger, 'Conflict between config and host options')
    # 3) filter , fields or records in import
    if args.operation == 'import' and (args.fields or args.filter or args.records):
        error(logger, 'Filds, filter and records options can be used only for export')
    # 4) csv and json conflict in import
    if args.operation == 'import' and args.csv_filename and args.json_filename:
        error(logger, 'Only one destination for data is allowed')
    # 5) screen in import
    if args.operation == 'import' and (args.screen):
        error(logger, 'Screen option can be used only for export')
    # 6) host without token or vise versa
    if not args.config_section and (not args.qradar_ip or not args.token):
        error(logger, 'Host or token option is missing')
    # 7) records and filters are not supported for networks
    if args.objects == 'networks' and (args.filter or args.records):
        error(logger, 'Filter and Records options are not supported for this export')
    # 8) records, filters, fieds  are not supported for operation fields
    if args.operation == 'fields' and (args.records or args.filter or args.fields):
        error(logger, 'Filter, Records and Fields options are not supported for this operation')
    # 9) Data is acceptable only for import
    if not args.operation in ['import', 'delete'] and args.values:
        error(logger, 'Data option cannot be used with this operation')
    # 10) Data cannot be used together with CSV or JSON
    if (args.json_filename or args.csv_filename) and args.values:
        error(logger, 'Data option cannot be used together with CSV or JSON options')
    # 11) Data do not works for Networks
    if (args.objects == 'networks') and args.values:
        error(logger, 'Data option cannot be used for networks')
    # 12) -t can be used only when CSV is referenced
    if args.tab and not args.csv_filename:
        error(logger, '-t switch can be used only along with CSV export/import')
    # 13) name can be used only with reference objects
    if args.refname and not(args.objects in ['refmap', 'refset', 'refmapset', 'reftable']):
        error(logger, 'Name cannot be used for objects other than Reference Data')
    # 14) for reference objects name must be used
    if not args.refname and (args.objects in ['refmap', 'refset', 'refmapset', 'reftable']):
        error(logger, 'Name must be given for all Reference Data objects')
    # 15) -r can be used only with import and reference data
    if args.rowbyrow and not(args.objects in ['refmap', 'refset', 'refmapset', 'reftable'] and args.operation == 'import'):
        error(logger, '-r can be used only with import and reference data')
    # 16) delete operation is allowed only for refatble object
    if args.operation == 'delete' and not(args.objects in ['reftable']):
        error(logger, 'You can delete only records in Reference Tables')
    # 17) aql can be used only with events object
    if args.objects != 'events' and args.aql:
        error(logger, 'AQL can be specified only for events')

    # Read the config
    if args.config_section:
        config = configparser.ConfigParser()
        try:
            config.read(CONFIG_NAME)
            logger.debug('CONFIG_NAME=' + CONFIG_NAME)
            args.qradar_ip = config[args.config_section.upper()]['QRADAR_IP']
            logger.debug('Read from config: QRADAR_IP=' + args.qradar_ip)
            args.token = config[args.config_section.upper()]['TOKEN']
            logger.debug('Read from config: TOKEN=' + args.token)
        except:
            error(logger,
                  'Configuration file "'+CONFIG_NAME+'" is not found, have wrong format or section ['+args.config_section.upper()+'] is missing')

    # Check CSV separator
    if args.tab:
        separator = '\t'
    else:
        separator = ','

    # Main operation selector
    found = False
    for object in endpoints:
        if (object['object'] == args.objects) and ((object['method'] == args.operation) or ((args.operation == 'fields')and (object['method'] == 'export'))):
            endpoint = object
            found = True
    if (not found) and (args.operation != 'fields'):
        not_implemented(logger)

    logger.debug('Endpoint = '+endpoint['endpoint'])

    qrclient = RestApiClient(args.qradar_ip, args.token,
                             endpoint, logger, args.filter, args.fields, args.records, args.refname, args.dateformat, args.rowbyrow, args.aql)

    if args.operation == 'export':
        logger.debug('Trying to export data')
        if args.aql:
            qrclient.prepare_aql(endpoint)
        result = qrclient.call_api()
        if args.csv_filename:
            qrclient.parse_json(args.objects)
            qrclient.save_csv(args.csv_filename, separator)
        if args.json_filename:
            qrclient.save_json(args.json_filename)
        if args.screen:
            if not args.csv_filename:
                qrclient.parse_json(args.objects)
            print(qrclient.show())

    if args.operation == 'fields':
        logger.debug('Printing list of fields')
        print('Fields available for export:')
        print(qrclient.fields)

    if args.operation == 'delete':
        logger.debug('Deleting records with specified keys')
        if args.json_filename:
            qrclient.load_json(args.json_filename)
        if args.csv_filename:
            qrclient.load_csv(args.csv_filename, separator)
            qrclient.jsonify(args.objects)
        if args.values:
            qrclient.parse_inline(args.values)
            qrclient.jsonify(args.objects)
        qrclient.delete(endpoint)
        logger.info(str(len(qrclient.dict))+' records deleted')

    if args.operation == 'import':
        logger.debug('Trying to import data')
        if args.json_filename:
            qrclient.load_json(args.json_filename)
            qrclient.parse_json(args.objects)
            qrclient.jsonify(args.objects)
        if args.csv_filename:
            qrclient.load_csv(args.csv_filename, separator)
            qrclient.jsonify(args.objects)
        if args.values:
            qrclient.parse_inline(args.values)
            qrclient.jsonify(args.objects)
        qrclient.write_api(endpoint)
        logger.info(str(len(qrclient.dict))+' records updated')
    logger.info('Done')
    exit(0)


if __name__ == '__main__':
    main()

