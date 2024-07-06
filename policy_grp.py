from panos import firewall, panorama
from panos.policies import Rulebase, SecurityRule, PreRulebase
from panos.objects import DynamicUserGroup, AddressGroup
import xml.etree.ElementTree as gfg
import getopt, sys, yaml, requests, os
from ipaddress import IPv4Address
from generate_xml2 import GenerateXmlFile
from panos import objects
from panos.firewall import Firewall
from collections import OrderedDict
from urllib3.exceptions import InsecureRequestWarning
# fw = Firewall("10.6.104.3", "admin", "Pa3250_2020")

# https://pandevice.readthedocs.io/en/latest/examples.html
# https://live.paloaltonetworks.com/t5/automation-api-discussions/how-to-start-with-pandievice-and-api/td-p/247563# -- policy
# https://pandevice.readthedocs.io/en/latest/getting-started.html#configure-your-device
# https://pandevice.readthedocs.io/en/stable/_modules/pandevice/objects.html#DynamicUserGroup
# https://pandevice.readthedocs.io/en/latest/module-firewall.html
# http://api-lab.paloaltonetworks.com/registered-user.html

class UserId:
    
    def __init__(self, fw_ip=None, username=None, passwd=None, pano=False, dgname='DG-460-jay', start_ip=IPv4Address('192.168.0.1'), num_users=100, vsys='vsys1', login=True):
        self.fw_ip = fw_ip
        self.panorama_used = pano
        if not self.panorama_used:
            self.fw = firewall.Firewall(fw_ip, api_username=username, api_password=passwd, vsys=vsys)
        else:
            self.pano = panorama.Panorama(fw_ip, api_username=username, api_password=passwd)
            self.fw = panorama.DeviceGroup(dgname)
            self.pano.add(self.fw).create()
            
        self.g = GenerateXmlFile(start_ip, num_users, login)
        self.user_group = OrderedDict()
        self.dags = list()
        self.dugs = list()
        self.sec_policy = OrderedDict()
        self.panorama = panorama
        
    def _get_group_count(self, num_users):
        if num_users < 10:
            # this will configure 5 groups with no users
            return 5
        # only first 50% of users would be configured under group, with each group having 10% users
        return (num_users//2)
    
    def write_xml_to_fw(self, filename, params):
        files = {'file': open(filename, 'rb')}
        print("files = ", files)
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        # response = requests.post('https://10.5.212.130/api/', files=dict(file='/Users/jswami/Desktop/Raptor/user_ip.txt'), params=params, verify=False)
        url = f'https://{self.fw_ip}/api/'
        response = requests.post(url, files=files, params=params, verify=False)
        print("## ", response.text)
    
    def __num_users_per_group(self, num_users, grp_num):
        # 10% of users will be there in every group
        # return int((0.1 * num_users) - 1)
        return num_users // grp_num
    
    def __num_users_per_dug(self, num_users):
        # 10% of users will be there in every in user-tag
        return int((0.25 * num_users) - 1)
    
    def create_user_groups(self, grp_num=None):
        # fw = firewall.Firewall("10.5.213.127", api_username="admin", api_password="Paloalt0")
        # uimap = fw.op('show user ip-user-mapping all', xml=True)
        # fw.userid.set_group('grp2', ['user2', 'user3'])
        count = 1
        start = 0
        end = per_grp_users = self.__num_users_per_group(len(self.g.user_ip.keys()) // 2, grp_num)
        # if grp_num is None:
            # grp_num = self._get_group_count(len(self.g.user_ip.keys()))
        # print(end)  
        while count <= grp_num:
            grpname = 'grp' + str(count)
            # if len(self.g.user_ip.keys()) >= 10:
            per_grp_user = list(self.g.user_ip.keys())[start:end]
            # print(per_grp_user)
            if not self.panorama_used:
                self.fw.userid.set_group(grpname, per_grp_user)
            else:
                # self.pano.userid.set_group(grpname, per_grp_user)
                pass
            self.user_group[grpname] = per_grp_user
            count += 1
            start = end
            end += per_grp_users
            # self.fw.userid.get_group_members(grpname)
            
    def __initialize_sec_rule(self):
        return {
            'service': 'any',
            'action': 'allow',
            'fromzone': ['any'],
            'tozone': ['any'],
            'source': ['any'],
            'destination': ['any'],
            'application': 'any'
        }
       
    def create_sec_policies_groups(self):
        i = 1
        # print(self.user_group)
        rule_start = 'rule_userid_'
        for j in self.user_group.keys():
            self.sec_policy[rule_start + str(i)] = self.__initialize_sec_rule()
            self.sec_policy[rule_start + str(i)]['source_user'] = [j]
            i += 1
        # print(i)
        user_list = list(self.g.user_ip.keys())
        incr = int(0.1*len(user_list) * 0.75)
        for j in range(int(len(user_list) * 0.75), len(user_list), incr):
            rulename = rule_start + str(i)
            if j + incr >= len(user_list):
                break
            self.sec_policy[rulename] = self.__initialize_sec_rule()
            self.sec_policy[rulename]['source_user'] = user_list[j: j + incr]
            i += 1
        # Add Dug sec policy
        for dug in self.dugs:
            rulename = rule_start + str(i)
            self.sec_policy[rulename] = self.__initialize_sec_rule()
            self.sec_policy[rulename]['source_user'] = ['dug2']
            i += 1
        
        print('Dags in list are: ', self.dags)
        for dag in self.dags:
            rulename = rule_start + str(i)
            self.sec_policy[rulename] = self.__initialize_sec_rule()
            self.sec_policy[rulename]['source'] = [dag]
            i += 1
        
    def install_sec_policy(self):
        # with open(filename, 'r') as file:
            # data = yaml.load(file, Loader=yaml.FullLoader)
        if not self.panorama_used:
             rb = Rulebase()
        else:
            rb = PreRulebase()
        self.fw.add(rb)
        for k, v in self.sec_policy.items():
            rl = SecurityRule(k, **v)
            rb.add(rl)
            rl.create()
        # self.fw.commit()
        
    def create_dug(self):
        # self.g.user_tag_map()
        self.g.usertag_range()
        dug2 = DynamicUserGroup('dug2', filter='tag_client or tag_server')
        self.fw.add(dug2)
        dug2.create()
        self.dugs.append('dug2')
        print(self.g.file_user_tag_map)
        return self.g.file_user_tag_map
    
    def create_dag(self):
        self.g.ip_tag_map()
        # dag1 = AddressGroup('dag2', dynamic_value='dag2c or dag2s')
        # fw.add(dag1)
        # dag1.create()
        # print(self.g.ip_tag)
        i = 0
        while i < len(self.g.ip_tag.keys()):
            dv = list(self.g.ip_tag.keys())[i] + ' or ' + list(self.g.ip_tag.keys())[i+1]
            dag1 = AddressGroup('dag' + str(i), dynamic_value=dv)
            self.fw.add(dag1)
            self.dags.append('dag' + str(i))
            dag1.create()
            i += 2
        return self.g.ip_tag_file
    
    def generate_mapping_file(self):
        # self.g.user_ip_map(users)
        # self.g.ip_tag_map()
        # self.g.user_tag_map()
        self.g.userip_range()
        return self.g.file_user_ip_map

# ud.create_dug()
'''
rl.CHILDMETHODS                        rl.delete(                             rl.fulltree(                           rl.refresh_variable(                   rl.update(
rl.CHILDTYPES                          rl.delete_similar(                     rl.group                               rl.refreshall(                         rl.url_filtering
rl.HA_SYNC                             rl.description                         rl.hip_profiles                        rl.refreshall_from_xml(                rl.uuid
rl.NAME                                rl.destination                         rl.icmp_unreachable                    rl.remove(                             rl.variables(
rl.ROOT                                rl.devicegroup(                        rl.insert(                             rl.remove_by_name(                     rl.virus
rl.SUFFIX                              rl.disable_server_response_inspection  rl.log_end                             rl.removeall(                          rl.vsys
rl.TEMPLATE_NATIVE                     rl.disabled                            rl.log_setting                         rl.rename(                             rl.vulnerability
rl.XPATH                               rl.dot(                                rl.log_start                           rl.retrieve_panos_version(             rl.wildfire_analysis
rl.about(                              rl.element(                            rl.move(                               rl.schedule                            rl.xml_merge(
rl.action                              rl.element_str(                        rl.name                                rl.service                             rl.xpath(
rl.add(                                rl.equal(                              rl.nearest_pandevice(                  rl.source                              rl.xpath_nosuffix(
rl.application                         rl.extend(                             rl.negate_destination                  rl.source_user                         rl.xpath_panorama(
rl.apply(                              rl.file_blocking                       rl.negate_source                       rl.spyware                             rl.xpath_root(
rl.apply_similar(                      rl.find(                               rl.negate_target                       rl.tag                                 rl.xpath_short(
rl.category                            rl.find_index(                         rl.panorama(                           rl.target                              rl.xpath_vsys(
rl.children                            rl.find_or_create(                     rl.parent                              rl.tozone                              
rl.create(                             rl.findall(                            rl.parse_xml(                          rl.tree(                               
rl.create_similar(                     rl.findall_or_create(                  rl.pop(                                rl.type                                
rl.data_filtering                      rl.fromzone                            rl.refresh(                            rl.uid 
'''

'''
rule = {
      'service': 'any',
      'action': 'allow',
      'fromzone': ['any'],
      'tozone': ['any'],
      'source': ['any'],
      'destination': ['any'],
      'application': 'any',
      'source_user': ['user1']
    }

# Security rules are children of a rulebase, so create the rulebase object and
# add it to the firewall as a child object.
rb = policies.Rulebase()
fw.add(rb)

# Load up the "configs" value here.  Each entry in "configs" is a python dict, but you could
# also just make it a list, it's up to you.
configs = []

# Now just iterate over each security rule and add it to the firewall.
rl = policies.SecurityRule('user123', **rule)
rb.add(rl)
rl.create()

fw.commit()

rule1: {
  "service":"any",
  "action":"allow",
  "fromzone":["any"],
  "tozone":["any"],
  "source":["any"],
  "destination":["any"],
  "application":"any",
  "source_user":["grp1"]
}
'''
