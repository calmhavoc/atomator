#!/usr/bin/python
#pip install ipaddr ipwhois censys shodan
# apt install golang; go get github.com/anshumanbh/tko-subs
from ipaddr import IPAddress, IPNetwork
from ipwhois import IPWhois
import pprint
import censys
from censys import *
import shodan
import sys
import pickle
from cmd import Cmd
import re
import os
import threading
import queue
import socket
import configparser
import json
from netaddr import IPNetwork
import functools
import validators
import time
import jsonlines
import subprocess


# sublist3r remove colors sed -i -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" sublist3r.txt

# TODO: threatcrowd.org API integration
"""
fix API config file
search: grahatwarfare and other bucket places like azure: output buckets and/or files
search:dnsdumpster:output host records
search:hackertarget.com:output bunch of stuff
"""

# TODO: add arin reverse whois to query netblock names and email addresses

# !!! Add certificate check to get domains for each IP



def strip_color(line):
    #return re.sub(r'\^\[\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]','',line)
    return re.sub(r'\x1b\[[0-9;]*[mGKF]','',line)

def return_ip(line):
    try:
        return re.search(r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b",line).group()
    except:
        return None


# Default error handling to keep from getting bounced on error
def catch_exception(f):
    import functools
    @functools.wraps(f)
    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            print ('Caught an exception in', f.__name__)
            print (str(e))
    return func


# Need a single object to hold our vars so we can save/restore
class Target(object):
    def __init__(self, target_name):
        self.name = target_name
        self.networks = []
        self.all_ips = []
        self.ipv6 = []
        self.singles = []
        self.master = {}
        self.netnames = []


# Begin command loop
class Begin(Cmd):
    '''starting out'''
    global target
    target = Target("default")
    config = configparser.ConfigParser()
    try:
        config.read('config.ini')
        SHODAN_API_KEY = config['API']['SHODAN_API_KEY']
        CENSYS_ID = config['API']['CENSYS_ID']
        CENSYS_SECRET = config['API']['CENSYS_SECRET']
        RISKIQ_USER = config['API']['RISKIQ_USER']
        RISKIQ_SECRET =  config['API']['RISKIQ_SECRET']
    except Exception as e:
        print (str(e))
        print ("No API keys detected, if you wish to use Shodan and Censys, update the config file and re-run")

    def emptyline(self):
        pass



    # @catch_exception
    def ip_in_network(self, ip):
        print (ip)
        ip = IPAddress(ip)
        for network in target.networks:
            if network != "":
                subnet = IPNetwork(network)
                if ip in subnet:
                    return True

        return False


    def get_rhost(self,ipaddr):
        try:
            fqdn = socket.getfqdn(ipaddr)
            return fqdn
        except Exception as e:
            print (str(e))
            return None


    def add_new_ip(self,ipaddr, source = ""):
        # global target
        ip = ipaddr
        # if is_ipv4(ip):
        if validators.ipv6(ip) or validators.ipv4(ip):
            if ip not in target.master.keys():
                target.master[ip]={}
                target.master[ip]['source']=['{}'.format(source)]
                target.master[ip]['fqdns'] = []
                target.master[ip]['ports']=[]
                target.master[ip]['cidr']=[]
                target.master[ip]['netname']=[]
            else:
                print ("{} already exists in the table".format(ip))
        else:
            print ("{} is not a valid IPv4 or IPv6 address".format(ip))



    # def get_iplist(self,cidr):
    #     ''' Add a known CIDR owned by the target eg: 8.8.8.0/23 '''
    #         netrange = IPNetwork(cidr)
    #     return

    def do_greet(self,line):
        print ("To get started, add some IPs manually ")


    def do_set_wordkingdir(self,wdir):
        os.chdir(wdir)

    def do_show_curdir(self,line):
        print(os.getcwd())
        
    def do_EOF(self,line):
        return True

    def do_exit(self,line):
        return True

    # def do_set_name(self,name):
    #     '''Set a name '''
    #     global target
    #     if name == "":
    #         target = Target(raw_input("Give your target a name: "))
    #     else:
    #         target = Target(name)

    def do_setup(self):
        pass

    @catch_exception
    def do_initial_osint(self,domain):
        ''' Given a domain, queries multiple sources to find associated IP addresses and subdomains
        # need to make working dir'''
        self.do_amass_gather(domain)
        #self.do_query_censys(domain)
        self.do_query_riskiq(domain)
        self.do_query_shodan_domain(domain)
        self.do_query_shodan_ips()

        pass

    def do_amass_gather(self,domain):
        global target
        domain = domain
        amass_cmd = "amass enum -d {0} -ip -o /tmp/amass-domains.txt".format(domain) # need to {0} workdir
        result = subprocess.run(amass_cmd.split(), stdout=subprocess.PIPE)

        b = result.stdout.decode().split("\n")

        for item in b:
            if ',' in item:
                fqdn = item.split(" ")[0]
                for ip in item.split(' ')[1].split(','):
                    print("Processing {}:{}".format(ip,item.split()[0]))
                    try:
                        self.add_new_ip(ip,source="amass")
                        if fqdn not in target.master[ip]['fqdns']:
                            target.master[ip]['fqdns'].append(fqdn)
                    except Exception as e:
                        print(str(e))
            else:
                fqdn = item.split(" ")[0]
                ip = item.split(" ")[1]
                self.add_new_ip(ip,source="amass")
                if fqdn not in target.master[ip]['fqdns']:
                    target.master[ip]['fqdns'].append(fqdn)




    # @catch_exception
    def do_add_ips_from_file(self,f_ips):
        ''' Add a single IP address manually, or add from a file. Expects a file that contains a single IP address per line
        add_ips <path to file>\nadd_ips 192.168.20.23'''
        global target
        
        if os.path.isfile(f_ips):
            try:
                with open(f_ips,'r') as f:
                    ips = f.read().splitlines()
                for ip in ips:
                    self.add_new_ip(ip,source=str(f_ips))
            except Exception as e:
                print (str(e))
        else:
            self.add_new_ip(f_ips,source="manually added")


    #@catch_exception
    def do_add_from_amass(self,f):
        ''' Expects a file comprised of json line data
        '''
        with jsonlines.open(f) as f:
            for obj in f:
                #try:
                fqdn = obj['name']
                ip = obj['addresses'][0]['ip']
                source = obj['source']

                self.add_new_ip(ip,source=source)
                if fqdn not in target.master[ip]['fqdns']:
                    target.master[ip]['fqdns'].append(fqdn)



    @catch_exception
    def do_add_from_discover(self, domain=None):
        '''Takes output from 'discover-scripts' found in /root/data/<domaindomain> and adds IP addresses,domains,
        hosts, etc to the db for parsing.
        e.g. parse_discover tigerlabs.net / or parse_discover <enter> to see options
        '''
        print(domain)

        if domain:
            folder = domain

        #path="/root/data/" 
        elif domain == "":
            discoverpath = os.path.expanduser('~')+'/data/'
            # options = '\n'.join([str(x) for x in os.listdir(home+'/data')])
            options = '\n'.join([str(x) for x in os.listdir(discoverpath)])
            print ("Enter the domain as found in ~/data/\n--")
            print (options,"\n--")
            domain = input("?  ")
            folder = discoverpath+domain

            if not os.path.isdir(folder):
                print (folder)
                print ("The path does not exist, try again\n")
                return 


#        if os.path.isdir(discoverpath+domain):
#            folder = discoverpath+domain

#        else:
#            print ("Looking for one of these:\n", '\n'.join([str(x) for x in os.listdir('/root/data')]))
#            return 
            
        try:
            hosts = folder+'/data/hosts.htm'
            with open(hosts,'r') as f:
                ips = f.read().splitlines()
        except:
            print ("Could not read file ",hosts)
            return

        for ip_addr in ips:
            ip = return_ip(ip_addr)
            if ip is not None and validators.ipv6(ip) or validators.ipv4(ip):# and is_ipv4(ip)):
                self.add_new_ip(ip,source="discover")
            else:
                print ("Not a valid IP: ",ip)

        try:
            subdomains = folder+'/data/subdomains.htm'
            with open(subdomains,'r') as f:
                domains_list = f.read().splitlines()
                # print domains_list
            for line in domains_list:
                try:
                    fqdn = line.split()[0]
                    ips = line.split()[1:]
                    for ip in ips:
                        ip = ip.rstrip(',')
                        if validators.ipv6(ip) or validators.ipv4(ip):
                            try:
                                self.add_new_ip(ip,source="discover")
                                if fqdn not in target.master[ip]['fqdns']:
                                    target.master[ip]['fqdns'].append(fqdn)
                            except Exception as e:
                                print ("Error processing ip:{}\n{}".format(ip,str(e)))
                                # print str(e)
                except Exception as e:
                    print("Failed: "+str(e))

        except:pass


    #@catch_exception
    def do_add_domains_from_file(self,f_domains):
        ''' Expects a file that has a domain on each line
        eg: ns1.mydomain.com '''
        with open(f_domains,'r') as f:
            domains_list = f.read().splitlines()

        for fqdn in domains_list:
            if validators.domain(fqdn):
                try:
                    hosts = socket.gethostbyname_ex(fqdn)[2]

                    for ip in hosts:
                        try:
                            self.add_new_ip(ip,source="file:{}".format(str(f_domains)))
                            if fqdn not in target.master[ip]['fqdns']:
                                target.master[ip]['fqdns'].append(fqdn)

                        except Exception as e:
                            print ("Error processing ip:{}\n{}".format(ip,str(e)))
                except Exception as e:
                    pass
                    #     # print str(e)
            else:
                print("Invalid: {}".format(fqdn))



    @catch_exception
    def do_query_shodan_domain(self,searchstring):
        '''Runs a shodan query on a provided domain
        e.g. shodan_query tigerlabs.net'''
        API_KEY = self.SHODAN_API_KEY
        api = shodan.Shodan(API_KEY)
        query = "hostname:"+searchstring #' '.join(searchstring)
        try:
            result = api.search(query)
            for service in result['matches']:
                ip = service['ip_str']
                port = service['port']
                fqdn = socket.getfqdn(ip)
                print ("Adding {}\t{}\t{}".format(ip,fqdn,port))

                self.add_new_ip(ip,source="{}".format('shodan'))
                # print "Adding {},{},{}".format(ip,fqdn,port)

                if fqdn not in target.master[ip]['fqdns']:
                    target.master[ip]['fqdns'].append(fqdn)

                if port not in target.master[ip]['ports']:
                    target.master[ip]['ports'].append(str(port))

        except Exception as e:
            print ('Error in Shodan: %s' % str(e))


    @catch_exception
    def do_query_shodan_ips(self, line):
        API_KEY = self.SHODAN_API_KEY
        api = shodan.Shodan(API_KEY)


        for ip in target.master.keys():
            try:
                time.sleep(1)
                query = "ip:"+ip #' '.join(searchstring)
                result = api.search(query)
                print("Querying: ",ip)
                for service in result['matches']:
                    ip = service['ip_str']
                    port = service['port']
                    fqdn = socket.getfqdn(ip)
                    print ("Adding: {}\t{}\t{}".format(ip,fqdn,port))




                    # Adding IP, and associated domains and ports 
                    self.add_new_ip(ip,source="{}".format('shodan'))
                    # print "Adding {},{},{}".format(ip,fqdn,port)

                    if fqdn not in target.master[ip]['fqdns']:
                        target.master[ip]['fqdns'].append(fqdn)

                    if port not in target.master[ip]['ports']:
                        target.master[ip]['ports'].append(str(port))


            except Exception as e:
                print('Error in Shodan IP search: {}'.format(e))

            



    @catch_exception
    def do_query_censys(self,searchstring):
        ''' Runs a censys query on the provided domain and if desired, adds results to the db
        e.g. censys_query tigerlabs.net '''

        global target
        censys_id = self.CENSYS_ID
        censys_secret = self.CENSYS_SECRET
        api = censys.ipv4.CensysIPv4(api_id=censys_id, api_secret=censys_secret)
        try:
            results = api.search(searchstring)

            for result in results:
                ip = result.get('ip')
                ports = result.get('protocols')#[0].split('/')[0]
                fqdn = socket.getfqdn(ip)
                print ("{},{},{}".format(ip, fqdn, ports))

                self.add_new_ip(ip,source="{}".format('censys'))
                        # print "Adding {},{},{}".format(ip,fqdn,ports)

                if fqdn not in target.master[ip]['fqdns']:
                    target.master[ip]['fqdns'].append(fqdn)

                for port in ports:
                    p = port.split('/')[0]
                    if p not in target.master[ip]['ports']:
                        target.master[ip]['ports'].append(p)

                            
        except Exception as e:
            print ("Error in censys: ",str(e))




    @catch_exception
    def do_query_riskiq(self,domain):
        '''Queries PassiveTotal/RiskIQ database for passive DNS entries for a provided domain
        eg: query_riskiq example.org '''
        from functools import partial
        import requests
        username = self.RISKIQ_USER
        key = self.RISKIQ_SECRET
        auth = (username,key)

        def passivetotal_get(path, query):
            base_url = 'https://api.passivetotal.org'
            url = base_url + path
            data = {'query': query}
            response = requests.get(url, auth=auth, json=data)
            return response.json()

        get_dns_passive = partial(passivetotal_get, '/v2/enrichment/subdomains')
        pdns_results_example = get_dns_passive(domain)
        domain_list = pdns_results_example['subdomains']
        for subdomain in domain_list:
            fqdn = "{}.{}".format(subdomain,domain)
            print (fqdn)
            try:
                ips = socket.gethostbyname_ex(fqdn)[2]
                for ip in ips:
                    try:
                        print ("{}\t{}".format(ip,fqdn))
                        self.add_new_ip(ip,source="{}".format('riskiq'))
                        if ip in target.master.keys():
                            target.master[ip]['fqdns'].append(fqdn)

                    except Exception as e:
                        print ("Error processing ip:{}\n{}".format(ip,str(e)))
            except socket.gaierror as e:
                # print str(e)
                pass



    # @catch_exception
    def do_query_whois(self,line):
        ''' Does a whois lookup on each IP address in the table. Will report back all network names and associated network ranges.
        This is useful for discovering network blocks that are used/owned by the target. 
        If new IP addresses are added to the table, you either have to run it again, or manually search and enter the info'''
        import warnings
        threads = 10
        resume = None

        print ("Performing lookup on {} addresses".format(len(target.master.keys())))
        
        def myfunct(my_queue):
            # for ip in target.master.keys():
            total = my_queue.qsize()
            while not my_queue.empty():
                ip_list = my_queue.get()
                for ip in ip_list:
                    # print ip
                    print ('\rItem: {}: {}'.format(ip, total)),
                    try:
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            whoisObj = IPWhois(ip)
                            whois = whoisObj.lookup_whois
                            try:
                                for netw in whois()['nets']:
                                    netname = netw['description']
                                    cidr = netw['cidr']
                                    target.master[ip]['netname']=netname
                                    target.master[ip]['cidr']=cidr
                                    if "whois" not in target.master[ip]['source']:
                                        target.master[ip]['source'].append('whois')
                                    if (netname,cidr) not in target.netnames:
                                        target.netnames.append((netname,cidr))
                            except:
                                print ("Exception for : ",ip)

                    except Exception as e:
                        print ("\nFailed to process: {}".format(ip))
                        print (str(e))
                    # i+=1
                # return 0
            tcount +=1
            print ("{}/10 Threads completed".format(str(tcount)))

        my_queue = queue.Queue()
        queue_size = my_queue.qsize()
        for ip in target.master.keys():
            my_queue.put([ip])

        tcount = 0
        for j in range(threads):
            t = threading.Thread(target=myfunct, args=(my_queue,))
            t.start()

    @catch_exception
    def do_query_hostnames(self,cidr):
        '''Does a host lookup on each address in the netrange. quer_hostnames 12.2.1.0/30'''

        for ip in IPNetwork(cidr):
            print (self.get_rhost(str(ip)))


    @catch_exception
    def do_add_netrange(self,cidr):
        ''' Add a known CIDR owned by the target eg: 8.8.8.0/23 '''
        ip=cidr.split('/')[0];whoisObj = IPWhois(ip);whois = whoisObj.lookup_whois
        for x in whois()['nets']:
            print (x['description'])

        host_lookup = input("Do a host lookup on each address (y/n)? ")

        if cidr != "":
            target.networks.append(cidr)
            netrange = IPNetwork(cidr)


        else:
            print ("You have to specify a cidr")
            netrange = input("Network? (eg:192.168.0.1/30)")


        if cidr != "":
            if host_lookup.lower() == 'y':
                for ip in netrange:
                    ip = str(ip)
                    self.add_new_ip(ip,source="{}".format('manual_cidr'))
                    fqdn = str(socket.getfqdn(ip))

                    if fqdn not in target.master[ip]['fqdns']:
                        target.master[ip]['fqdns'].append(fqdn)
                        print ("Added: {}\t{}".format(ip,fqdn))
            else:
                for ip in netrange:
                    ip = str(ip)

                    if ip not in target.master.keys():
                        self.add_new_ip(ip,source="{}".format('manual_cidr'))



    # @catch_exception
    def do_remove_keywords_from_values(self,searchstring):
        '''Sometimes on a bulk add, a value gets added all over the table that isn't helpful. For example:
        if you do a shodan search that returns a lot of IPs and the PTR record is the default ISP record, it
        will get added to the table and clutter it up. This will look at each value and remove it if the string is found. 
        eg: remove_keywords_from_values comcast'''
        master = target.master

        for ip,value in master.items():
            for val in master[ip]:
                for item in master[ip][val]:
                    if searchstring in item:
                        print (searchstring)
                        print (item)
                        master[ip][val].remove(item)
                        print ("Removed {} from {}".format(item,ip))




    @catch_exception
    def do_remove_netrange(self,cidr):
        '''Removes a range of IP addresses from the table
        eg: remove_netrange 10.10.1.0/16 ''' 
        netrange = IPNetwork(cidr)
        for ip in netrange:
            ip = str(ip)
            if ip in target.master.keys():
                del target.master[ip]
                print ("Removed: {}".format(ip))


    @catch_exception
    def do_show_ips(self,line):
        ''' 'Shows all single IP addresses discovered '''
        print (target.all_ips)


    @catch_exception
    def do_show_master(self,line):
        ''' Shows the complete dictionary table that has so for been added to the current session'''
        print (target.master)


    @catch_exception
    def do_print_scan_strings(self,nmap):
        '''Prints to screen a list of nmap strings, one IP per line to be used for scanning.
        Accepts an nmap string eg: print_scan_strings -sV -O -p 1-1024 '''
        master = target.master.keys()
        if nmap == "":
            nmap = "-sV --top-ports=100"
        for ip in master:
            print ("nmap {} {}".format(ip,nmap))



    @catch_exception
    def do_show_network_blocks(self,line):
        '''Displays network block names and associated network ranges in the table.
        This is so you don't have to run get_netinfo again unless you've added additional IP addresses '''
        target.netnames.sort()
        for netname in target.netnames:print (netname)

            
    def do_print_domains(self,line):
        domains = []
        # master = target.master.keys()
        for ip in target.master.keys():
            for domain in target.master[ip]['fqdns']:
                if validators.ipv6(domain) or validators.ipv4(domain) or 'arpa' in domain:
                    pass
                else:
                    domains.append(domain)

        unique_domains = set(domains)
        for i in unique_domains: print(i)
        
        print("Total:\t{}").format(len(unique_domains))
        
        
    @catch_exception
    def do_print_json(self,line):
        ''' Prints the current working table to the screen in json format'''
        print (json.dumps(target.master,indent=1))


    @catch_exception
    def do_print_csv(self,line):
        '''Prints the current working table to the screen in csv format '''
        master = target.master
        for ip in master.keys():
            sources,fqdns,ports,cidr,netmane = "","","","",""
            sources = "/".join(master[ip]["source"])
            fqdns = "/".join(master[ip]["fqdns"])
            ports = "/".join(master[ip]["ports"])
            try:
                cidr = "/".join(master[ip]["cidr"])
                netname = "/".join(master[ip]["netname"])
            except:
                cidr = ""
                netname = ""
            try: 
                print ("{},{},{},{}".format(str(ip),str(fqdns),str(ports),str(sources)))
            except Exception as e:
                print ("Error printing CSV: ",str(e))


    @catch_exception
    def do_print_report(self,line):
        '''Prints to screen a readable output of the  table as IP DOMAIN '''
        invalid = []
        master = target.master
        for ip in sorted(master.keys()):
            for fqdn in master[ip]['fqdns']:
                if validators.ipv6(ip) or validators.ipv4(ip) or 'arpa' in fqdn:
                    invalid.append('{}\t{}'.format(ip,fqdn))
                else:
                    print ("{}\t{}".format(str(ip),str(fqdn)))

         # Need to add additional report items: unique IPs with totals, IPs to networks (aws, google, etc) 


    @catch_exception
    def do_save_metasploit_xml(self,line):
        '''Output an xml file that can be parsed and imported into MSF Database '''
        xml_hdr = '''<?xml version="1.0" encoding="UTF-8"?>
        <MetasploitV5>
        <generated time="2016-12-30 00:18:45 UTC" user="root" project="default" product="framework"/>
        <hosts>'''

        xml_host = '''<host>
            <id>{0}</id>
            <created-at>2016-12-30 00:16:08 UTC</created-at>
            <address>{1}</address>
            <mac></mac>
            <comm></comm>
            <name>{2}</name>
            <state>alive</state>
            <os-name></os-name>
            <os-flavor/>
            <os-sp/>
            <os-lang/>
            <arch/>
            <purpose> {3} </purpose>
            <info></info>
            <comments></comments>
            <scope />
            <host_details></host_details>'''

        xml_svc = '''<service>
              <id></id>
              <host-id>{0}</host-id>
              <created-at>2016-12-30 00:16:08 UTC</created-at>
              <port>{1}</port>
              <proto>tcp</proto>
              <state>open</state>
              <name>unk</name>
              <updated-at>2016-12-30 00:16:08 UTC</updated-at>
              <info></info>
              </service>'''

        xml_null_svc = '''<services>
              <service>
              <id></id>
              <host-id></host-id>
              <created-at></created-at>
              <port></port>
              <proto></proto>
              <state></state>
              <name></name>
              <updated-at></updated-at>
              <info></info>
              </service>
        </services>'''

        xml_footer = '''
        </hosts>
        </MetasploitV5>'''

        f = open('./msfout.xml','w')
        hid = 1
        f.write(xml_hdr)
        for key in target.master.keys():
            current = target.master[key]
            ip_addr = key
            fqdn = ''
            netname = ''
            sources = ''
            if current.__contains__('fqdn'):
                fqdn = current['fqdn']
            if current.__contains__('netname'):
                netname=current['netname']
            if current.__contains__('source'):
                sources = " ".join(current['source'])
                # print sources
            # f.write(xml_host.format(hid,ip_addr,fqdn,sources,netname))
            f.write(xml_host.format(hid,ip_addr,fqdn,sources))
            # print '''
            # id={0}
            # address={1}
            # comments={2}'''.format(hid,ip_addr,netname)
            if current.__contains__('ports'):
                f.write('<services>\n')
                for port in current['ports']:
                    f.write(xml_svc.format(hid,port))
                f.write("  </services>")
            else:
                f.write(xml_null_svc)
            f.write("</host>\n")
            hid += 1
        f.write(xml_footer)
        f.close()



    @catch_exception
    def do_save_as_csv(self,name):
        '''Saves the current table as a csv file that contains:
        IP Address , Ports , FQDN , sources , netname , CIDR '''
        f = open('./'+name,'w')
        f.write("IP Address,Ports,FQDN,sources,netname,CIDR\n")
        for key in target.master.keys():
            try:
                current = target.master[key]
                ip_addr = key
                fqdn = ''
                netname = ''
                sources = ''
                ports = ''
                cidr = ''

                if current.__contains__('fqdns'):
                    # fqdn = current['fqdns']
                    fqdn = '|'.join(str(p) for p in (current['fqdns']))
                if current.__contains__('netname'):
                    netname=current['netname']
                if current.__contains__('source'):
                    sources = " ".join(current['source'])
                    # print sources
                if current.__contains__('ports'):
                    ports = '|'.join(str(p) for p in (current['ports']))

                if current.__contains__('cidr'):
                    cidr=current['cidr']


                f.write("{},{},{},{},{}\n".format(ip_addr,ports,fqdn,sources,netname,cidr))
            except Exception as e:
                print ("Error in csv: {}".format(e))
        f.close()


    @catch_exception
    def do_save_working_table(self, name ):
        '''Saves the current table in the form of a python pickle in the current directory with the specified name.
        eg: save_working_table <savename>'''
        with open('./'+ name + '.pkl', 'wb') as f:
            pickle.dump(target, f, pickle.HIGHEST_PROTOCOL)

    @catch_exception
    def do_load_master(self,name ):
        '''Loads a previously saved table (python pickle) into the current workspace. This will overwrite all data so save before if desired '''
        global target
        with open('./' + name + '.pkl', 'rb') as f:
            target = pickle.load(f)


    @catch_exception
    def do_interact(self,line):
        ''' Drop to a python shell to interact with the current dataset.\n ** CTRL-D returns to workspace, exit() kills the space ** '''
        import code
        print ("CTRL-D to exit\n")
        # global target
        try:
            code.interact(local=dict(globals(), **locals()))
        except SystemExit:
            pass
        # import pdb
        # pdb.set_trace()

    @catch_exception
    def default(self, line):       
        """Called on an input line when the command prefix is not recognized.
           In that case we execute the line as Python code.
        """
        try:
            exec(line) in self._locals, self._globals
        except Exception as e:
            print (e.__class__, ":", e)


if __name__ == '__main__':
    Begin().cmdloop()
