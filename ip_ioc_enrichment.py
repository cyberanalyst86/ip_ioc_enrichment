import pandas as pd
from mandiant_search_module import *
from virustotal_module import *
from abuseidb_module import *


def main():

    abuseipdb_list = []
    virustotal_list = []
    vt_detection = []
    country = []
    vt_link = []
    abuseConfidenceScore = []
    isp = []
    domain = []
    hostnames = []
    total_reports = []
    abuseipdb_link = []

    id_lst = []
    mscore_lst = []
    type_lst = []
    value_lst = []
    is_publishable_lst = []
    last_updated_lst = []
    first_seen_lst = []
    last_seen_lst = []

    Associated_Actors_lst = []
    Associated_Malware_lst = []
    Associated_Campaigns_lst = []
    Associated_Tools_lst = []

    Mandiant_Url_lst = []

    ip_ioc_input = input("Enter excel file path: ")

    df = pd.read_csv(ip_ioc_input)

    for index, row in df.iterrows():

        ip = row["ip"]

        print(ip)

        # --------------------------------Get Abuseipdb Results---------------------------#

        print("#----------------------------abuseipdb--------------------------------#\n")

        abuseipdb_attributes, abuseipdb_attribute_value_list, abip_result_url = query_abuseipdb_metadata(ip)

        # --------------------------------Get VT Results---------------------------#

        print("#----------------------------VirusTotal--------------------------------#\n")

        virustotal_attributes, vt_attribute_value_list, vt_result_url = query_ip_address_virustotal_metadata(ip)

        vt_detection.append(vt_attribute_value_list[0])
        country.append(vt_attribute_value_list[4])
        vt_link.append(vt_result_url)
        abuseConfidenceScore.append(abuseipdb_attribute_value_list[1])
        isp.append(abuseipdb_attribute_value_list[3])
        domain.append(abuseipdb_attribute_value_list[4])
        hostnames.append(abuseipdb_attribute_value_list[5])
        total_reports.append(abuseipdb_attribute_value_list[6])
        abuseipdb_link.append(abip_result_url)

        print("#----------------------------Mandiant--------------------------------#\n")

        id, mscore, type, value, is_publishable, last_updated, first_seen, last_seen, \
            Mandiant_Url, Associated_Actors_list, Associated_Malware_list, \
            Associated_Campaigns_list, Associated_Tools_list = mandiiant_search(ip)

        id_lst.append(id)
        mscore_lst.append(mscore)
        type_lst.append(type)
        value_lst.append(value)
        is_publishable_lst.append(is_publishable)
        last_updated_lst.append(last_updated)
        first_seen_lst.append(first_seen)
        last_seen_lst.append(last_seen)

        Associated_Actors_lst.append(Associated_Actors_list)
        Associated_Malware_lst.append(Associated_Malware_list)
        Associated_Campaigns_lst.append(Associated_Campaigns_list)
        Associated_Tools_lst.append(Associated_Tools_list)

        Mandiant_Url_lst.append(Mandiant_Url)

    df['virustotaldetection']=vt_detection
    df['country']=country
    df['virustotallink']=vt_link
    df['abuseConfidenceScore']=abuseConfidenceScore
    df['isp']=isp
    df['domain']=domain
    df['hostnames']=hostnames
    df['total_reports']=total_reports
    df['abuseipdblink']=abuseipdb_link
    #df["Mandiant id"] = id_lst
    df["mscore"] =  mscore_lst
    df["type"] = type_lst
    df["value"] = value_lst
    df["is_publishable"] = is_publishable_lst
    df["last_updated"] = last_updated_lst
    df["first_seen"] = first_seen_lst
    df["last_seen"] = last_seen_lst
    df["Associated_Actors"] = Associated_Actors_lst
    df["Associated_Malware"] = Associated_Malware_lst
    df["Associated_Campaigns"] = Associated_Campaigns_lst
    df["Associated_Tools"] = Associated_Tools_lst
    df["Mandiant Url"] = Mandiant_Url_lst

    df.to_excel("ip_ioc_enrichment.xlsx", index=False)

    print("completed")

if __name__ == "__main__":
    main()