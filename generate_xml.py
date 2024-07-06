import xml.etree.ElementTree as gfg
import requests, os, getopt, sys
from ipaddress import IPv4Address
from collections import OrderedDict
import threading


class GenerateXmlFile:
    
    def __init__(self, start_ip=IPv4Address('192.168.0.1'), num_users=100, login=True):
        self.user_ip_file = None
        self.ip_tag_file = None
        self.user_tag_file = None
        self.start_ip_user = start_ip
        self.user_tag = OrderedDict()
        self.user_ip = OrderedDict()
        self.ip_tag = OrderedDict()
        self.num_users = int(num_users)
        self.login = login
    
    def write_file(self, filename, tree, map_type):
        with open (filename, "wb") as files :
            tree.write(files)
        if map_type == 'user_ip':
            self.user_ip_file = filename
        if map_type == 'ip_tag':
            self.ip_tag_file = filename
        if map_type == 'user_tag':
            self.user_tag_file = filename
    
        return filename
    
    def _user_ip_map(self, start=1, end=50000, filename='user_ip.txt'):
        start_ip = self.start_ip_user
        root = gfg.Element("uid-message")
        root.tail = "\n"
        m1 = gfg.Element("version")
        root.append (m1)
        m1.text = '2.0'
        m1.tail = "\n"
        
        m2 = gfg.Element("type")
        root.append (m2)
        m2.text = 'update'
        m2.tail = "\n"
        
        m3 = gfg.Element("payload") 
        root.append (m3)
        m3.tail = "\n"
        
        if self.login:
            m4 = gfg.SubElement(m3, "login")
        else:
            m4 = gfg.SubElement(m3, "logout")
        # root.append (m4)
        m4.tail = "\n"
        
        # gfg.SubElement(m3, "entry", name="user1", ip="192.168.1.14", timeout="20000").tail = "\n"
        # gfg.SubElement(m3, "entry", name="domain\duser1", ip="192.168.1.1", timeout="20000").tail = "\n"
        
        count = start
        ip = start_ip + start
        print('START IP: ', ip)
        self.user_list = list()
        user_count = count
        # users=100
        while  count <= int(end) and count <= self.num_users :
            user_name = 'xmluser' + str(user_count)
            gfg.SubElement(m4, "entry", name=user_name, ip=str(ip), timeout="20000").tail = "\n"
            ip = ip + 1
            # user_name = 'user' + str(count)
            count += 1
            # self.user_list.append(user_name)
            self.user_ip[user_name] = ip
            gfg.SubElement(m4, "entry", name="domain\d" + user_name, ip=str(ip), timeout="20000").tail = "\n"
            ip = ip + 1
            # self.user_list.append("domain\d" + user_name)
            self.user_ip["domain\d" + user_name] = ip
            user_name = 'xmluser' + str(count)
            count += 1
            user_count += 1
        print('END IP: ', ip)
        # tree = gfg.ElementTree(root)
        self.write_file(filename, gfg.ElementTree(root), 'user_ip')
        
    def userip_range(self):
        self.file_user_ip_map = OrderedDict()
        self.file_user_ip_map['user_ip_1.txt'] = 1
        if self.num_users > 50000:
            numfiles = self.num_users // 50000 + 1
            count = 50001
            for i in range(2, numfiles + 1):
                filename = 'user_ip_' + str(i) + '.txt'
                self.file_user_ip_map[filename] = count
                count += 50000
            thread_list = []
            for k, v in self.file_user_ip_map.items():
                thread_list.append(threading.Thread(target=self._user_ip_map, args=(v, v+49999, k)))
            for thread in thread_list:
                thread.start()
            for thread in thread_list:
                thread.join()
        else:
            self._user_ip_map(start=1, end=self.num_users)
        return self.file_user_ip_map
    
    
    def ip_tag_map(self):
        # client ip = 172.168.1.10
        # server ip = 172.168.1.11
        # client ip subnet = 172.168.2.0/24
        # server ip subnet = 172.168.3.0/24
        # client ip range = 172.168.4.1 - 172.168.4.254
        # server ip range = 172.168.5.1 - 172.168.5.254
        root = gfg.Element("uid-message")
        root.tail = "\n"
        
        m2 = gfg.Element("type")
        root.append (m2)
        m2.text = 'update'
        m2.tail = "\n"
        
        m3 = gfg.Element("payload") 
        root.append (m3)
        m3.tail = "\n"
        
        m4 = gfg.SubElement(m3, "register") 
        # m3.append (m4)
        m4.tail = "\n"
    
        # gfg.SubElement(m3, "entry", name="user1", ip="192.168.1.14", timeout="20000").tail = "\n"
        # gfg.SubElement(m3, "entry", name="domain\duser1", ip="192.168.1.1", timeout="20000").tail = "\n"
        info = {'client_ip': "172.168.1.10", 'server_ip': "172.168.1.11", 'client_subnet': "172.168.2.0/24", 'server_subnet': "172.168.3.0/24", 'client_range': "172.168.4.1-172.168.4.254", 'subnet_range': "172.168.5.1-172.168.5.254"}
        for k, v in info.items():
            m5 = gfg.SubElement(m4, "entry", ip=v)
            m6 = gfg.SubElement(m5, "tag")
            m7 = gfg.SubElement(m6, "member")
            # m6.append (m7)
            m7.text = k
            m7.tail = "\n"
            self.ip_tag[k] = v
        
        self.write_file('eg_iptag.txt', gfg.ElementTree(root), 'ip_tag')
        
    def _user_tag_map(self, start, end, filename='user_tag_1.txt'):
        print('inside user tag map')
        root = gfg.Element("uid-message")
        root.tail = "\n"
        
        m2 = gfg.Element("type")
        root.append (m2)
        m2.text = 'update'
        m2.tail = "\n"
        
        m3 = gfg.Element("payload") 
        root.append (m3)
        m3.tail = "\n"
        
        m4 = gfg.SubElement(m3, "register-user") 
        # m3.append (m4)
        m4.tail = "\n"
        
        # start = (len(self.user_ip.keys()) // 2) + 1
        end_limit = int(len(self.user_ip.keys()) // 1.33)
        # for user in list(self.user_ip.keys())[start+1:end]:
        i = start
        print('####', start, end, end_limit)
        print(list(self.user_ip.keys())[i])
        user_ip_list = list(self.user_ip.keys())
        mid = (end+start) // 2
        while i <= end and i <= end_limit:
            # print(i)
            user = user_ip_list[i]
            m5 = gfg.SubElement(m4, "entry", user=user)
            m5.tail = "\n"
            m6 = gfg.SubElement(m5, "tag")
            # m6.append (m7)
            m6.tail = "\n"
            m7 = gfg.SubElement(m6, "member")

            if i < mid:
                self.user_tag[user] = 'tag_client'
                m7.text = 'tag_client'
            else:
                self.user_tag[user] = 'tag_server'
                m7.text = 'tag_server'

            # self.user_tag[user] = 'tag_client'
            # m7.text = 'tag_client'
            m7.tail = "\n"
            i += 1
            # print(i, end, end_limit)
        # print(self.user_tag)
        self.write_file(filename, gfg.ElementTree(root), 'user_tag')
        print('exit user tag map')
        
    def usertag_range(self):
        start = (len(self.user_ip.keys()) // 2) + 1
        end = int(len(self.user_ip.keys()) // 1.33)
        self.file_user_tag_map = OrderedDict()
        self.file_user_tag_map['user_tag_1.txt'] = start
        print(end-start)
        if end - start > 50000:
            numfiles = (end - start) // 50000 + 1
            print(numfiles)
            count = start + 50000
            for i in range(2, numfiles + 1):
                filename = 'user_tag_' + str(i) + '.txt'
                self.file_user_tag_map[filename] = count
                count += 50000
            thread_list = []
            for k, v in self.file_user_tag_map.items():
                thread_list.append(threading.Thread(target=self._user_tag_map, args=(v, v+49999, k)))
                print('Thread list is: ', k)
            for thread in thread_list:
                thread.start()
            for thread in thread_list:
                thread.join()
        else:
            self._user_tag_map(start, end)
        print('exit user tag range')
        return self.file_user_tag_map
    
    
'''
numfiles = self.num_users // 50000 + 1
self.file_map = OrderedDict()
self.file_map['user_ip_1.txt'] = 1
count = 50001
for i in range(2, numfiles):
    filename = 'user_ip_' + str(i) + '.txt'
    self.file_map[filename] = count
    count += 50000
thread_list = []
for k, v in self.file_map.items():
    thread_list.append(threading.Thread(target=self._user_ip_map, args=(v, v+49999, k)))
for thread in thread_list:
    thread.start()
for thread in thread_list:
    thread.join()
'''
        
# g = GenerateXmlFile()
# g.ip_tag_map()
# g.user_ip_map()
# g.user_tag_map()
