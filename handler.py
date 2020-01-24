#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import zmq
import time
import pprint
import json
import requests
import yaml
eventTag = False

#title
title=''
#attributes that are being observed
attributes=[]
#Attribute values
values=[]
#Event infos
evtInfos=[]
#Organisation IDs
orgs=[]
#Tags
tags=[]
#Normal splunk key
token=''
#Alert splunk key
alert_token=''
#Trigger to alert everytime
trigger=''
#URL
url=''
#Splunk Index
index=''

#Parse YAML configs
def input_configs(path,info):
    global attributes,values,evt_infos,orgs,tags,token,alert_token,trigger,title,url,index
    with open(path, 'r') as stream:
        try:
            data = yaml.safe_load(stream) 
            configs_verif(data)            
            title = data['title'] if element_verif(data['title']) else 'Configs'    
            attributes = data['attributes'] if element_verif(data['attributes']) else []
            values = data['values'] if element_verif(data['values']) else []
            evt_infos = data['evtInfos'] if element_verif(data['evtInfos']) else []
            orgs = data['orgs'] if element_verif(data['orgs']) else []
            tags = data['tags'] if element_verif(data['tags']) else []
            token = data['normalKey']
            alert_token = data['alertKey']
            trigger = data['trigger'] if element_verif(data['trigger']) else False
            url = data['url']
            index = data['index']
            if info:
                print_info()
        except yaml.YAMLError as exc:
            print(exc)

#Verify critical conditions on config file
def configs_verif(data):
    if data == None:
        print("Couldn't find any config")
        quit()
    if not element_verif(data['normalKey']) or not element_verif(data['alertKey']) or not element_verif(data['url']) or not element_verif(data['index']):
        print('Splunk Normal Key, Alert Key, URL, index required')
        quit()

#Verify if a config element is empty
def element_verif(element):
    if element == None or element == [None]:
        return False
    return True

#Print config info
def print_info():
    print('####{}####'.format(title))
    print('\nAttributes: \n{}'.format(attributes))
    print('\nValues: \n{}'.format(values))
    print('\nEvent Infos: \n{}'.format(evt_infos))
    print('\nOrganisations: \n{}'.format(orgs))
    print('\nTags: \n{}'.format(tags))
    print('\nTrigger: \n{}'.format(trigger))

#Sends data to splunk, each time a attribute with the matching conditions is found
def splunk_post(value,dataType,eventID,eventInfo,objectID,key):    
    authHeader = {'Authorization': 'Splunk {}'.format(key)}
    jsonDict = {"index":index, "event": { "value": value, "dataType": dataType, "eventID": eventID, "eventInfo": eventInfo, "objectID": objectID } }
    r = requests.post(url, headers=authHeader, json=jsonDict, verify=False)
    print (r.text)


#Uses all of the functions below
def conditions(misp):    
    if(attribute_type(misp) and add(misp)):        
        if verif_empty():
            return True
        else:
            if orgid(misp) or event_info(misp) or eventTag == True:
                return True
    return False
    
#Verify if some info is empty
def verif_empty():
    if evtInfos == orgs == tags == []:
        return True
    return False

#Verify Attribute Type
def attribute_type(json_misp):
    for attribute in attributes:
        if attribute.upper() in json_misp["Attribute"]["type"].upper():
            return True
    return False

#Verify organization id
def orgid(json_misp):
    for org in orgs:
        if org in json_misp["Event"]["orgc_id"]:
            return True
    return False

#Verify event info
def event_info(json_misp):
    for evtInfo in evtInfos:
        if evtInfo in json_misp["Event"]["info"].upper():
            return True
    return False

#Verify event tags
def tag_list(json_misp):    
    global eventTag
    if add(json_misp):
        for tag in tags:       
            for mispTag in json_misp["EventTag"]:
                if mispTag["Tag"]["name"].upper() in tag.upper():
                    eventTag = True
    return eventTag

#Verify if is new event
def add(json_misp):
    if "add" in json_misp["action"]:
        return True
    return False

#Verify attribute value
def alert_condition(json_misp):    
    if trigger == True:
        print('Trigger')
        return True
    for value in values:
        if value.upper() in json_misp["Attribute"]["value"].upper():      
            print("Alert")      
            return True
    return False


pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)

parser = argparse.ArgumentParser(description='Generic ZMQ client to gather events, attributes and sighting updates from a MISP instance')
parser.add_argument("-s","--stats", default=False, action='store_true', help='print regular statistics on stderr')
parser.add_argument("-p","--port", default="50000", help='set TCP port of the MISP ZMQ (default: 50000)')
parser.add_argument("-r","--host", default="127.0.0.1", help='set host of the MISP ZMQ (default: 127.0.0.1)')
parser.add_argument("-o","--only", action="append", default=None, help="set filter (misp_json, misp_json_event, misp_json_attribute or misp_json_sighting) to limit the output a specific type (default: no filter)")
parser.add_argument("-t","--sleep", default=0.1, help='sleep time (default: 0.1)', type=int)
parser.add_argument("-c","--config",default="config.yaml",help="set config file path (default: .../currentPath/config.yaml)")
parser.add_argument("-i","--info",default=False,action ="store_true",help="print info about configs (default:False)")
args = parser.parse_args()

if args.only is not None:
        filters = []
        for v in args.only:
                filters.append(v)
        sys.stderr.write("Following filters applied: {}\n".format(filters))
        sys.stderr.flush()

port = args.port
host = args.host
context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect ("tcp://%s:%s" % (host, port))
socket.setsockopt(zmq.SUBSCRIBE, b'')

poller = zmq.Poller()
poller.register(socket, zmq.POLLIN)

if args.stats:
    stats = dict()

input_configs(args.config,args.info)
while True:
    socks = dict(poller.poll(timeout=None))
    if socket in socks and socks[socket] == zmq.POLLIN:
            message = socket.recv()
            topic, s, m = message.decode('utf-8').partition(" ")
            if args.only:
                if topic not in filters:
                        continue
            json_misp=json.loads(m)
            #If detected something
            if not "status" in json_misp.keys():
                print("####BEGIN####")
                print(topic)
                print(m)
                print(json_misp.keys())
                print("#####END#####")
                if topic == "misp_json_event":
                    tag_list(json_misp)
                if topic == "misp_json_attribute":
                    eventType = json_misp["Attribute"]["type"]
                    value = json_misp["Attribute"]["value"]                    
                    eventID = json_misp["Event"]["id"]
                    eventInfo = json_misp["Event"]["info"]
                    objectID = json_misp["Attribute"]["object_id"]    
                                                    
                    if conditions(json_misp):
                        if alert_condition(json_misp):                            
                            splunk_post(value,eventType,eventID,eventInfo,objectID,alert_token)                            
                        else:                            
                            splunk_post(value,eventType,eventID,eventInfo,objectID,token)
                            print('Without alert')
                    else:
                        print('Discarded')
            else:
                continue
            
            if args.stats:
                stats[topic] = stats.get(topic, 0) + 1
                pp.pprint(stats)

time.sleep(args.sleep)