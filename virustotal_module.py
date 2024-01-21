import requests
import json
import os
import re
import yaml
from yaml.loader import SafeLoader
import pandas as pd
import datetime

#-----------------------------VirusTotal_Metadata-------------------------------#

def query_ip_address_virustotal_metadata(ip_address):


    with open(
        "api.yaml") as f:
        conf = yaml.load(f, Loader=SafeLoader)

    apikey = conf['vt_api']['vt_api_key']

#-----------------------------Definition-------------------------------#

    ip_query_result_url = "https://www.virustotal.com/gui/ip-address/"
    json_level_3 = ["regional_internet_registry" , "network", "tags","country","as_owner"]
    json_level_4 = ["harmless", "malicious", "suspicious" , "undetected"]

    query_url = "https://www.virustotal.com/api/v3/ip_addresses/" + str(ip_address)

    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }

    num_detection_list = []
    attribute_list = []

#-----------------------------Get Response-------------------------------#
    try:

        response = requests.get(query_url, headers=headers)

    except FileNotFoundError:

        print('virustotal query error')

    json_object = json.loads(response.text)

    for attr in json_level_4:

        num_detection_list.append(json_object["data"]["attributes"]["last_analysis_stats"][attr])

    sum_of_detection = sum(num_detection_list)
    detection = json_object["data"]["attributes"]["last_analysis_stats"]["malicious"]

    detection = "detection : " + str(detection) + " of " + str(sum_of_detection)

    attribute_list.append(detection)

    for attr in json_level_3:

        try:

            attribute_list.append(str(attr) + " : " + str(json_object["data"]["attributes"][attr]))

        except KeyError:

            attribute_list.append("private ip")
            print('private ip')

# -----------------------------Format Attributes-------------------------------#

    # -----------------------------Convert Epoch Time-------------------------------#

    #last_analysis_date = attribute_list[5].split(":")

    #epoch_time = datetime.datetime.fromtimestamp(int(last_analysis_date[1]))

    #attribute_list[5] = "last_analysis_date : " + str(epoch_time)

    # -----------------------------Get Detection Breakdown------------------------------#

    last_analysis_stats = json_object["data"]["attributes"]["last_analysis_stats"]

    last_analysis_stats_lst_item = "detection breakdown : " + str(last_analysis_stats)

    attribute_list.append(last_analysis_stats_lst_item)

    # -----------------------------Get VT URL ------------------------------#

    vt_result_url = ip_query_result_url + str(ip_address)

    attribute_list.append("VT link : " + str(vt_result_url))

# -----------------------------Get Attribute List Json String------------------------------#

    jsonStr = json.dumps(attribute_list, indent=2)

    return jsonStr, attribute_list , vt_result_url