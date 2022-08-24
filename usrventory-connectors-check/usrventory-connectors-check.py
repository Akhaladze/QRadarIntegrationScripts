import psycopg2
import pypyodbc
import os
from dotenv import load_dotenv
import logging
import logging.handlers
from rfc5424logging import Rfc5424SysLogHandler
import psycopg2.extras
import json
import pyodbc
import datetime
import requests

__author__ = "Georgiy Akhaladze"
__version__ = "0.1.0"
__maintainer__ = "Georgiy Akhaladze"
__email__ = "georgiy_akhaladze@service-team.biz"
__status__ = "Prod"

date_now = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

#Inventory connectors check

#- owerall status of inventory
#- connectors check
#- worker_status



def load_config():
    with open('/home/user/soc_scripts/usrventory-connectors-check/config.json', 'r') as conf_data:
        conf_data = json.load(conf_data)
    return conf_data

def get_connectors_list(inventory_base_url, connectors_list_url, sec):
    url = inventory_base_url + connectors_list_url
    connectors_list = requests.get(url, headers = {"SEC": sec, "accept": "application/json"}, verify=False)
    return connectors_list.json()
    
def get_connector_status(inventory_base_url, connector_status_url, connector_id, sec):
    url = inventory_base_url + connector_status_url + '/' + connector_id
    connector_status = requests.get(url, headers = {"SEC": sec, "accept": "application/json"}, verify=False)
    
    return connector_status.json()
    

def get_connector_error_status(inventory_base_url, connectors_error_status_url, sec):
    url = inventory_base_url + connectors_error_status_url
    connector_error_status = requests.get(url, headers = {"SEC": sec, "accept": "application/json"}, verify=False)
    return connector_error_status.json()
    
def search_black_list (con_id, exclude):
    for keyval in exclude:
        con_id_tmp = str(keyval)
        con_id = str(con_id)
        if (con_id == con_id_tmp):
            find_connector = True
            break
        else:
            find_connector = False
          
    return find_connector    
        
def get_worker_status(inventory_base_url, worker_status, sec):
    url = inventory_base_url + worker_status
    worker_status = requests.get(url, headers = {"SEC": sec, "accept": "application/json"}, verify=False)
    return worker_status.json()


def main():

    conf_data=load_config()
    inventory_base_url=conf_data["inventory_base_url"]
    connectors_list_url=conf_data["connectors_list_url"]
    connector_status_url=conf_data["connector_status_url"]
    worker_status_url=conf_data["worker_status_url"]
    connectors_error_status_url=conf_data["connectors_error_status_url"]
    sec=conf_data["SEC"]
    
    zabbix_preffix = conf_data["zabbix_preffix"]
    exclude = conf_data["exclude"]
    
    Error_number = 0
    
    #print(exclude)
    
#Connectors error status    
    connectors = get_connector_error_status(inventory_base_url, connectors_error_status_url, sec)
    connector_status=""
    for connector in connectors:

        search_black_list_result = search_black_list(connector["_id"], exclude)
        
        if (search_black_list_result==False):
            connector_status = connector_status + "::" + str(Error_number)
            connector_status = connector_status + " ID: " + connector["_id"]
            connector_status = connector_status + " Name: " + connector["name"]
            connector_status = connector_status + " ErrorMsg: " + connector["error"][0:55] + "\r" 
            Error_number = Error_number + 1
        
    #print ("Error_number:")
    print (Error_number)
    connector_status.replace('"', '')
    #connector_status.replace('v4563\u0000', '')
    
    if (Error_number <= 0):
        connector_status = "No Errors"
        command_zabbix_inventory_connector_status = 'zabbix_sender -z 10.18.31.5 -s soc-imperva-con.hq.gng.ua -k ' + zabbix_preffix + '.connector.status -o "Ready"'
    else:
        command_zabbix_inventory_connector_status = 'zabbix_sender -z 10.18.31.5 -s soc-imperva-con.hq.gng.ua -k ' + zabbix_preffix + '.connector.status -o "Not Ready"'
        
        
    command_zabbix_inventory_connector_status_log = 'zabbix_sender -z 10.18.31.5 -s soc-imperva-con.hq.gng.ua -k ' + zabbix_preffix + '.connector.status.log -o "' + connector_status + '"'
    #print (command_zabbix_inventory_connector_status_log)
    os.system(command_zabbix_inventory_connector_status)
    os.system(command_zabbix_inventory_connector_status_log)
    
    
    
   

#Worker status 

    worker_status = get_worker_status(inventory_base_url, worker_status_url, sec)
    
    
    if (worker_status["connectorsCount"]):
        
        command_zabbix_inventory_worker_status = 'zabbix_sender -z 10.18.31.5 -s soc-imperva-con.hq.gng.ua -k ' + zabbix_preffix + '.wrk.status -o 100'
        command_zabbix_inventory_worker_log = 'zabbix_sender -z 10.18.31.5 -s soc-imperva-con.hq.gng.ua -k ' + zabbix_preffix + '.wrk.status.log -o "Connectors count: "' + str(worker_status["connectorsCount"])

    else:
        command_zabbix_inventory_worker_status = 'zabbix_sender -z 10.18.31.5 -s soc-imperva-con.hq.gng.ua -k ' + zabbix_preffix + '.wrk.status -o 0'
        command_zabbix_inventory_worker_log = 'zabbix_sender -z 10.18.31.5 -s soc-imperva-con.hq.gng.ua -k ' + zabbix_preffix + '.wrk.status.log -o "Not Ready"'

                
    os.system(command_zabbix_inventory_worker_status)
    os.system(command_zabbix_inventory_worker_log)





if __name__ == "__main__":
    main()
