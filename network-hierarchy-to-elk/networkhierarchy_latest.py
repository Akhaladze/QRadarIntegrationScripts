import csv
import elasticsearch
import datetime
import subprocess

es = elasticsearch.Elasticsearch([{'host':'localhost', 'port':'9200'}])
date_now = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S+02:00')

csvFilePath = 'net.csv'

subprocess.call(['python3', 'qapi-export.py', 'export', 'networks', '--host', 'siem.domain.com', '--token', 'TTTTTOOOOKKKEEENNN', '--csv', f'{csvFilePath}'])

data = {}

try:
    es.indices.delete(index='networkhierarchy_latest')
except:
    print ('wow')

with open(csvFilePath) as csvFile:
    csvReader = csv.DictReader(csvFile)
    for rows in csvReader:
        data.update(rows)
        data.update({'@timestamp': date_now})
        es.index(index='networkhierarchy_latest', body=data)

