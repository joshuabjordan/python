#/usr/bin/env python
import hashlib
import json
import requests
from zipfile import ZipFile
from io import BytesIO
import os.path
from slackclient import SlackClient
import shelve

url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip'
meta = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta'


def get_json(mh):
    res = requests.get(url)
    json_zipped = ZipFile(BytesIO(res.content))
    cve_json = ''
    for name in json_zipped.namelist():
        for line in json_zipped.open(name).readlines():
            cve_json += line.decode('utf-8')
    h = hashlib.sha256(cve_json.encode('utf-8')).hexdigest().upper()
    if mh == h:
        return cve_json
    return


def main():
    res = requests.get(meta)
    for line in res.text.split('\n'):
        if 'sha256' in line:
            mh = line.split(':')[1].strip()
    cve_json = get_json(mh)

    while cve_json == None:
        cve_json = get_json(mh)
        # add in counter and send slack message after a set number of failed attempts
    cve_dict = json.loads(cve_json)

    # checking to see if file exsits, if not write dictionary to a file
    if os.path.isfile('data.json'):
        print("File exsits, comparing dictionaries..")
        with open('data.json', 'r') as fp:
            data = json.load(fp)
            # dictionary comparision
    
            # print(data)
    else:
        with open('data.json', 'w') as fp:
            json.dump(cve_dict, fp)

    for cve in cve_dict['CVE_Items']:
        cve_id = cve['cve']['CVE_data_meta']['ID']
        cve_desc = cve['cve']['description']['description_data'][0]['value']
        d = ('{} : {}'.format(cve_id, cve_desc) +
             ' ' 'https://nvd.nist.gov/vuln/detail/' + cve_id)
        # print(d)

    # add in comparing so each time the script is run you don't have a million notfications in slack, only populates the new ones


if __name__ == '__main__':
    main()
