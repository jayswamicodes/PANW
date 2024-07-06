import requests, os, sys, getopt
import argparse
from requests.packages import urllib3
from bs4 import BeautifulSoup
from generate_xml2 import GenerateXmlFile
from policy_grp import UserId
import threading
from datetime import datetime

# sending traffic sudo mz ens192 -A 192.168.29.77 -B 192.168.1.10 -t icmp "echoreq" -c 5
# curl -X GET 'https://10.5.212.130/api/?type=keygen&user=admin&password=Paloalt0' --insecure
# curl -k --form file=@user_ip.txt "https://10.5.212.130/api/?type=user-id&action=set&vsys=vsys1&key=LUFRPT1tcTY0SGxCeG5tcG9hU2tNSkcrajIxSmtIODg9OE1nSE9aQTkzYjdWREhaeU1NVU9YYVIvbXVDUzNSR0FteFhleWY2SEhlZEFZNjUrWFdLbXRVclAybTE0QkJhQQ=="
# -ip '10.5.212.131' --username 'admin' --password 'Admin123' --numusers 10000 -dg PA-5400-Vsys1 -gn 7 -pr 
# -ip '10.5.212.131' --username 'admin' --password 'Admin123' --numusers 10000 -dg PA-5400-Vsys1 -gn 7 -pr
# -ip '10.5.212.131' --username 'admin' --password 'Admin123' --numusers 10000
    
parser = argparse.ArgumentParser(description='Process some arguments')
parser.add_argument('-ip', '--ipaddress', type=str, help='pass firewall ip or panorama ip')
parser.add_argument('-u', '--username', type=str, help='firewall login username')
parser.add_argument('-p', '--password', type=str, help='firewall login password')
parser.add_argument('-nu', '--numusers', default=100, help='number user ip mappings')
parser.add_argument('-gn', '--groupnum', default=2, help='number of groups')
parser.add_argument('-v', '--vsys', default='vsys1', help='vsys id')
parser.add_argument('-da', '--dag', action='store_true', help='default False, if True will configure ip-tag mapping & DAG')
parser.add_argument('-du', '--dug', action='store_true', help='default False, if True will configure DUG using user-ip mapping')
parser.add_argument('-pr', '--panorama', action='store_true', help='default False, means dut must be firewall, pass True to enable dut as panorama')
parser.add_argument('-dg', '--device_group', default='DG-460-jay', help='Pass the Device group on panorama to configure')
parser.add_argument('-l', '--login', action='store_false', help='default True will login users, if False will logout users')
parser.add_argument('-po', '--policies', action='store_false', help='default True will login users, if False policies wont be configured')

argsc = parser.parse_args()
print(argsc)

params = (
    ('type', 'keygen'),
    ('user', argsc.username),
    ('password', argsc.password),
)

uid = UserId(argsc.ipaddress, argsc.username, argsc.password, argsc.panorama, argsc.device_group, num_users=argsc.numusers, login=argsc.login)
# filename = uid.generate_mapping_file(argsc.numusers)
# filename = uid.create_dug()
# print("filename = ", filename)
# response = requests.get('https://10.5.212.130/api/', params=params, verify=False)

#NB. Original query string below. It seems impossible to parse and
#reproduce query strings 100% accurately so the one below is given
#in case the reproduced version is not "correct".
# curl -X GET 'https://10.5.212.130/api/?type=keygen&user=admin&password=Paloalt0' --insecure
url = f'https://{argsc.ipaddress}/api/?type=keygen&user={argsc.username}&password={argsc.password}'
response_key = requests.get(url, verify=False)
# print(response_key.text)
soup = BeautifulSoup(response_key.text, 'html.parser')
print(soup.key.text)
key = soup.key.text
# response_key = 'LUFRPT1tU29KUHh4RHBPTmNXR0xvZUFQTlpYQXV6MUk9VUJsQlI4d05qRTBNVDU2VVBHTVVlOVZpaGpLaFd6dEFwd3ZnUFVxTGVaMTdsL3pHV2hHbmVEQUJnL2t3U3A3Tw=='

params = (
    ('type', 'user-id'),
    ('action', 'set'),
    ('vsys', argsc.vsys),
    ('key', key),
)

print('Generate user ip mapping file at: ', datetime.now().time())
filename = uid.generate_mapping_file()
print(filename)


print('Start configure user ip mapping at : ', datetime.now().time())
thread_list_file = []
for k in filename.keys():
    thread_list_file.append(threading.Thread(target=uid.write_xml_to_fw, args=(k, params)))
    #$# uid.write_xml_to_fw(k, params)

if argsc.dug:
    print('Generate user tag mapping file at: ', datetime.now().time())
    filename = uid.create_dug()
    print("file name is :", filename)
    print('Start configure user tag mapping at : ', datetime.now().time())
    # filename = {'user_tag_1.txt': 1, 'user_tag_2.txt': 2}
    for k in filename.keys():
        thread_list_file.append(threading.Thread(target=uid.write_xml_to_fw, args=(k, params)))
        uid.write_xml_to_fw(k, params)

if argsc.dag:
    print('Generate ip tag mapping file at: ', datetime.now().time())
    filename = uid.create_dag()
    uid.write_xml_to_fw(filename, params)


# uid = UserId(argsc.ipaddress, argsc.username, argsc.password)
# uid.generate_mapping_file()

if argsc.login:
    if int(argsc.groupnum) > 0:
        print('create user groups')
        print('Configure user group mapping at : ', datetime.now().time())
        uid.create_user_groups(grp_num=int(argsc.groupnum))
        print('Done Configuring user group mapping at : ', datetime.now().time())

    if argsc.policies:
        print('create sec policy')
        print('Create & Configure security policies at : ', datetime.now().time())
        uid.create_sec_policies_groups()
        uid.install_sec_policy()
        print('Done configuring security policies at : ', datetime.now().time())


#NB. Original query string below. It seems impossible to parse and
#reproduce query strings 100% accurately so the one below is given
#in case the reproduced version is not "correct".
# cmd = 'curl -k --form file=@user_ip.txt ' + '"https://10.5.212.130/api/?type=user-id&action=set&vsys=vsys1&key={}"'.format(key)
# print(cmd)
# os.system(cmd)
# post_line = 'https://10.5.212.130/api/?type=user-id&action=set&vsys=vsys1&key=' + key
# response = requests.post(post_line, verify=False)

