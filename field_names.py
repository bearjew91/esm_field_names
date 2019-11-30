import json, requests, urllib3, base64
from difflib import SequenceMatcher
from getpass import getpass
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)






#User Inputs
def start():
    user_name = base64.b64encode(bytes(input("Enter SIEM Username\n"), 'utf-8')).decode('utf-8')
    passwd = base64.b64encode(bytes(getpass(), 'utf-8')).decode('utf-8')
    siem_ip = input("Enter the IP address of the SIEM\n")
    return user_name, passwd, siem_ip

def login(user_name, passwd, siem_ip):
    print("Login")
    url = 'https://'+siem_ip+'/rs/esm/v2/login'
    params = {"username":user_name,"password":passwd,"locale":"en_US","os":"Win32"}
    headers = {'Content-Type': 'application/json'}
    data = json.dumps(params)
    resp = requests.post(url, data=data,headers=headers, verify=False)
    if resp.status_code in [400, 401]:
        print('Invalid username or password for the ESM')
    elif 402 <= resp.status_code <= 600:
            print('ESM Login Error:', resp.text)
    headers['Cookie'] = resp.headers.get('Set-Cookie')
    headers['X-Xsrf-Token'] = resp.headers.get('Xsrf-Token')
    return headers

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def get_filter_fields(headers, siem_ip):
    print("Loading Filter Filelds")
    field_name = input("Enter Field Name - Case Sensitive:\n")
    url = "https://"+siem_ip+"/rs/v1/query/fields"
    resp = requests.get(url, headers=headers, verify=False)
    data = json.loads(resp.text)
    for field in data:
        if field["name"] == field_name:
            alert_field = field["alertField"]
            break
    try:
        alert_field
        print("\nFields with the same Field ID as {0}:\n".format(alert_field))
        for find in data:
            if find["alertField"] == alert_field:
                print(find["name"])
    except:
        print("No field named '{0}' found".format(field_name))
        match = {"name":"", "ratio":0, "alertField":""}
        for names in data:
            match_ratio = SequenceMatcher(None, field_name, names["name"]).ratio()
            match_name = names["name"]
            alert_field = names["alertField"]
            if float(match_ratio) > match["ratio"]:
                match["ratio"] = round(match_ratio, 2)
                match["name"] = match_name
                match["alertField"] = alert_field
        ans = input("Did You Mean '{0}'? - y/n\n".format(match["name"]))
        if ans == "y":
            for find in data:
                if find["alertField"] == match["alertField"]:
                    print(find["name"])
        else:
            pass
            


        
user_name, passwd, siem_ip = start()
headers = login(user_name, passwd, siem_ip)
get_filter_fields(headers, siem_ip)


























