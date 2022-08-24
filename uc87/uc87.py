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
from collections import Counter
from heapq import merge
import requests
from requests.auth import HTTPBasicAuth
import urllib3
import sys

__author__ = "Georgiy Akhaladze"
__version__ = "0.1.0"
__maintainer__ = "Georgiy Akhaladze"
__email__ = "georgiy_akhaladze@service-team.biz"
__status__ = "Prod"

urllib3.disable_warnings()
load_dotenv()


#Load data from UserVentory

#Load data from QRadar

#Iterate users from UV(main) to QRadar
# - add new user if not present
# - iterate QRadar with UV and delete not matched users from QRadar
# - save file with status logging


date_now = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')


#Loading data and config
def load_config():
    with open('/home/user/soc_scripts/uc87/config.json', 'r') as conf_data:
        conf_data = json.load(conf_data)
    return conf_data
    
def load_users_qradar():
    with open('/home/user/soc_scripts/uc87/users-qradar.json', 'r') as users_qradar:
        os.system('cp /home/user/soc_scripts/uc87/users-qradar.json /home/user/soc_scripts/uc87/temp/users-qradar' + date_now + '.json')
        users_qradar = json.load(users_qradar)
    return users_qradar

def load_users_userventory(domain):
    with open('/home/user/soc_scripts/uc87/users-userventory-' + domain + '.json', 'r') as users_userventory:
        users_userventory = json.load(users_userventory)
    return users_userventory
    
def adduser(base_url_qradar_adduser, value, source_user, sec):
    #command_add_user_from_qradar_refset = 'curl -S -X POST -H "SEC: 81b9f7a3-6b09-4187-b3b7-800a30aec7da" -H "Version: 17.0" -H "Accept: application/json" "https://soc-siem.hq.gng.ua/api/reference_data/sets/RD%253AUC87-3-Accounts%2520with%2520the%2520privileges%2520of%2520viewing%2520the%2520attributes%2520of%2520the%2520LAPS?value=' + value +  '&source=GAkhaladzeScript" -k'
    #os.system(command_add_user_from_qradar_refset)
    result = requests.post(base_url_qradar_adduser + value + source_user, headers = {"SEC": sec, "accept": "application/json"}, verify=False)
    return 0
    
def deluser(base_url_qradar_deluser, value, source_user, sec):
    #command_del_user_from_qradar_refset = 'curl -S -X DELETE -H "SEC: 81b9f7a3-6b09-4187-b3b7-800a30aec7da" -H "Version: 17.0" -H "Accept: application/json" "https://soc-siem.hq.gng.ua/api/reference_data/sets/RD%253AUC87-3-Accounts%2520with%2520the%2520privileges%2520of%2520viewing%2520the%2520attributes%2520of%2520the%2520LAPS?value=' + value +  '" -k'
    #os.system(command_del_user_from_qradar_refset)
    result = requests.delete(base_url_qradar_deluser + '/' + value, headers = {"SEC": sec, "accept": "application/json"}, verify=False)
    return result


#Initializing logger

syslog_server = os.getenv("SYSLOG_SRV")
syslog_port = os.getenv("SYSLOG_PORT")
log_file_path = os.getenv("LOGS_PATH")
syslog_script_path = os.getenv("SYSLOG_SCRIPT_PATH")
syslog_script_name = os.getenv("SYSLOG_SCRIPT_NAME")
rootLogger = logging.getLogger('')
rootLogger.setLevel(logging.INFO)

sh = Rfc5424SysLogHandler(address=(syslog_server, syslog_port), utc_timestamp=True)

rootLogger.addHandler(logging.FileHandler(log_file_path))

rootLogger.addHandler(sh)


class LEEF_Logger:
    """LEEF LOGGER"""

    # LEEF Headers
    product_vendor = None
    

    def __init__(self, product_vendor, delimiter=" "):
        """ Define the LEEF Headers for the application logging """

        self.product_vendor = product_vendor
        

        #if delimiter not in ['\t', '|', '^']:
            #raise ValueError("Delimeter must be '\\t', '|' or '^'")
        self.delimiter = delimiter

    def logEvent(self, event_id, keys):
        """
        Log an event
        """
        return self._createEventString(event_id, keys)

    def _createEventString(self, event_id, keys):
        header = self._createHeader(event_id)

        values = sorted([(str(k) + "=" + str(v))
                         for k, v in iter(keys.items())])

        payload = ' '.join(values)
        #payload = '\t'.join(values)

        return (header + payload)

    def _createHeader(self, event_id):
        return "{0} {1}". \
               format(self.product_vendor, event_id )



def main():
    leef = LEEF_Logger('timestamp=' + date_now, delimiter="  ")
    event = {'ScriptName' : '"' + syslog_script_name + '"', 
             'ScriptFolder' : '"' + syslog_script_path + '"', 
             'ScriptStage' : '"Load data from userventory (1/4)"'}
             
    msg = leef.logEvent('ScriptStatus="Success" ', event)
    rootLogger.info(msg)
    

    conf_data=load_config()
    base_url_inventory=conf_data["base_url_inventory"]
    basic_params_inventory=conf_data["basic_params_inventory"]
   
    sec=conf_data["SEC"]
    source_user=conf_data["source_user"]
    base_url_qradar_adduser=conf_data["base_url_qradar_adduser"]
    base_url_qradar_deluser=conf_data["base_url_qradar_deluser"]
    
    user_data = []
    user_data_items = []
    
    print ("Loading user data...")
    ii=0
    #ittems=""
    for config_domain in conf_data["config"]:
 
        
        member_of_group=config_domain["member_of_group"]
        domain=config_domain["domain"]
       
        response = requests.get(base_url_inventory, params = {"start": 0,"size":100, "sortBy":"name", "filter": {member_of_group, domain}}, headers = {"SEC": sec, "accept": "application/json"}, verify=False)
        
        print(response.request.url)
        
        
        #print(response.request.body)
        #print(response.request.headers)
        #exit()
        
        user_data = response.json()
        print ("Domain: " + domain + " Groups: " + member_of_group)
        print("Total Users Counter " + str(user_data["total"]))
        
        
        
        
        #print ('NUMBER' + str(ii))
        for user_data_item in user_data["items"]:    
            print(user_data_item["name"]["default"])
        
        
        
        
        user_data = user_data["items"]
        user_data_items += user_data
        
        
        
        ii=ii+1
    
    #Logging stage userventory data downloaded
    
    leef = LEEF_Logger('timestamp=' + date_now, delimiter="  ")
    event = {'ScriptName' : '"' + syslog_script_name + '"', 
             'ScriptFolder' : '"' + syslog_script_path + '"', 
             'ScriptStage' : '"Load data from Qradar refset (2/4)"'}
             
    msg = leef.logEvent('ScriptStatus="Success" ', event)
    rootLogger.info(msg)


    
    
    
    command_get_users_from_qradar = 'curl -S -X GET -H "Range: items=0-200" -H "Version: 16.0" -H "SEC: 81b9f7a3-6b09-4187-b3b7-800a30aec7da" -H "Accept: application/json" "https://soc-siem.hq.gng.ua/api/reference_data/sets/RD%253AUC87-3-Accounts%2520with%2520the%2520privileges%2520of%2520viewing%2520the%2520attributes%2520of%2520the%2520LAPS?fields=number_of_elements%2C%20data%20%28value%29" -k > users-qradar.json'
    os.system(command_get_users_from_qradar)



    #print ("Iteration user QRadar...")
    users_qradar=load_users_qradar()



#Iterate users in QRadar and compare with users in Userventory    
    for qradar_user in users_qradar["data"]:
        qr_user=qradar_user["value"]
        
    
        for user_ventory_user in user_data_items:
            uv_user=user_ventory_user["name"]["default"]
            uv_user = '@'.join(uv_user.split('@')[:-1])
       
            if (uv_user == qr_user):
                #print ('match ' + uv_user)
                break
        else:
            print ('Delete User from RefSet ' + qr_user)
            
            try:
                req_del = deluser(base_url_qradar_deluser, qr_user, source_user, sec)
           
            except Exception as e:
                print('Error:' + e + req_del.status_code)
                print('Success delete record')
            

    #Logging stage iteration users acros QRadar and Userventory
    
    leef = LEEF_Logger('timestamp=' + date_now, delimiter="  ")
    event = {'ScriptName' : '"' + syslog_script_name + '"', 
             'ScriptFolder' : '"' + syslog_script_path + '"', 
             'ScriptStage' : '"Compare users list beetween Qradar and UserVentory (3/4)"'}
             
    msg = leef.logEvent('ScriptStatus="Success" ', event)
    rootLogger.info(msg)

                   

#Iterate users in Userventory and compare with users in QRadar    
    for user_ventory_user in user_data_items:
        uv_user=user_ventory_user["name"]["default"]
        uv_user = '@'.join(uv_user.split('@')[:-1])
        present_in_qradar=0
            


        for qradar_user in users_qradar["data"]:
            qr_user=qradar_user["value"]
            
            if (uv_user == qr_user):
                #print ('match ' + uv_user)
                present_in_qradar=1
                break
            
        if (present_in_qradar==0):
            
            adduser(base_url_qradar_adduser, uv_user, source_user, sec)
            print ('Add User to RefSet ' + uv_user)

    
    #Logging stage: QRadar refset synced with UserVentory
    
    leef = LEEF_Logger('timestamp=' + date_now, delimiter="  ")
    event = {'ScriptName' : '"' + syslog_script_name + '"', 
             'ScriptFolder' : '"' + syslog_script_path + '"', 
             'ScriptStage' : '"QRadar refset synced with UserVentory (4/4)"'}
             
    msg = leef.logEvent('ScriptStatus="Success" ', event)
    rootLogger.info(msg)   
           
    

if __name__ == "__main__":
    main()

