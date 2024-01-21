import requests
import json
import yaml
from yaml.loader import SafeLoader
from requests.auth import HTTPBasicAuth
import pandas as pd
import re
from dateutil import parser


def mandiiant_search(ip):
    # ----------------------------Get Credentials from File-----------------------------#
    with open(
            "api.yaml") as f:
        conf = yaml.load(f, Loader=SafeLoader)

    publickey = conf['mandiant_api']['publickey']
    privatekey = conf['mandiant_api']['privatekey']

    APIv3_key = publickey
    APIv3_secret = privatekey

    # ----------------------------Get Mandiant API Token-----------------------------#

    API_URL = 'https://api.intelligence.fireeye.com/token'
    headers = {
        'grant_type': 'client_credentials'
    }
    r = requests.post(API_URL, auth=HTTPBasicAuth(APIv3_key, APIv3_secret), data=headers)
    data = r.json()
    auth_token = data.get('access_token')

    url = "https://api.intelligence.mandiant.com/v4/indicator" \
        # bearer_token = "insert bearer token"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name",
        "Content-Type": "application/json"
    }
    post_body = {
        "requests": [
            {
                "values": [ip]
            }
        ]
    }
    params = None

    # ----------------------------Declare variables-----------------------------#

    resp = requests.post(url=url, headers=headers, data=json.dumps(post_body))

    if resp.status_code == 200:

        df = pd.DataFrame(resp.json()["indicators"])

        for index, row in df.iterrows():

            id = row["id"]
            mscore = row["mscore"]
            type = row["type"]
            value = row["value"]
            is_publishable = row["is_publishable"]

            first_seen_dt = parser.parse(row["first_seen"])
            first_seen = (first_seen_dt.date())

            last_seen_dt = parser.parse(row["last_seen"])
            last_seen = (last_seen_dt.date())

            last_updated_dt = parser.parse(row["last_updated"])
            last_updated = (last_updated_dt.date())

            Mandiant_Url = "https://advantage.mandiant.com/indicator/ipv4/" + str(row["value"])

            try:

                Associated_Actors = []
                Associated_Malware = []
                Associated_Campaigns= []
                Associated_Tools = []


                for i in row["attributed_associations"]:

                    if re.match(".*threat-actor.*", i["type"]):

                        Associated_Actors.append(i["name"])
                        Associated_Malware.append("")
                        Associated_Campaigns.append("")
                        Associated_Tools.append("")

                    elif re.match(".*malware.*", i["type"]):

                        Associated_Malware.append(i["name"])
                        Associated_Actors.append("")
                        Associated_Campaigns.append("")
                        Associated_Tools.append("")

                    elif re.match(".*campaign.*", i["type"]):

                        Associated_Campaigns.append(i["name"])
                        Associated_Actors.append("")
                        Associated_Malware.append("")
                        Associated_Tools.append("")

                    elif re.match(".*tools.*", i["type"]):

                        Associated_Tools.append(i["name"])
                        Associated_Actors.append("")
                        Associated_Malware.append("")
                        Associated_Campaigns.append("")

                    else:

                        Associated_Actors.append("")
                        Associated_Malware.append("")
                        Associated_Campaigns.append("")
                        Associated_Tools.append("")

                Associated_Actors_list = Associated_Actors
                Associated_Malware_list = Associated_Malware
                Associated_Campaigns_list = Associated_Campaigns
                Associated_Tools_list = Associated_Tools


            except KeyError:

                Associated_Actors_list = ""
                Associated_Malware_list = ""
                Associated_Campaigns_list = ""
                Associated_Tools_list = ""

    else:

        id = ""
        mscore = ""
        type = ""
        value = ""
        is_publishable = ""
        last_updated = ""
        first_seen = ""
        last_seen = ""
        Mandiant_Url = ""
        Associated_Actors_list = ""
        Associated_Malware_list = ""
        Associated_Campaigns_list = ""
        Associated_Tools_list = ""


    return id, mscore, type, value, is_publishable, last_updated, first_seen, last_seen, \
        Mandiant_Url, Associated_Actors_list, Associated_Malware_list, \
        Associated_Campaigns_list, Associated_Tools_list





