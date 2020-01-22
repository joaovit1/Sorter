# **Sorter**

Sorter is a python script to watch for new MISP data and sort by chosen conditions

It allows a config file in YAML, which have the following fields:

* **title**: Config file title
* **attributes**: The attribute types you will watch for
* **values**: The values inside of the attributes, that if found, will send an alert to Splunk
* **evtInfos**: Search for specific words in event infos, ex: *'OSINT'*
* **orgs**: Monitor for specific organisations
* **tags**: Search for specific tags in events
* **normalKey**: Splunk key used to send normal data
* **alertKey**: This key is intended to be different from normal key, to send data to other Splunk source, which will trigger an alert
* **trigger**: Accepts true or false, every element that fit the conditions, will be sent to the Splunk alert source
* **url**: Splunk url collector

## Accepts Lists

- [ ] Title
- [x] Attributes
- [x] Values
- [x] EvtInfos
- [x] Orgs
- [x] Tags
- [ ] Normal Key
- [ ] Alert Key
- [ ] Trigger
- [ ] URL

# How it works

It all begins on putting the attributes under watch on the attributes field, if you dont want any alert, you can repeat the normal key on the alert key and you are ready to go!

You can search for specific values on attributes, attributes under watch will be sent to splunk anyway, but if an attribute value matchs the searched one, it will be sent to the alert key.

The EvtInfos, Orgs and Tags works together, if you put any value on one of them, only attribute events that matches at least one of the conditions will be sent to Splunk, even if it matches the attribute type.

The trigger value is used to alert everything that matches the conditions, only the alert key will be used, a good way to use that is to put some restrict conditions in the EvtInfos, Orgs and Tags and alert all of them.

# How to use (example)

Here's a basic example of a YAML config file that searches for *filename*, *link*, *hostname* and *domain* attributes.
It searches for values containing my organisation name in case of a targeted threat and alerts me in that cases

```YAML
title: 'General Configs'
attributes:
  - 'filename'
  - 'link'
  - 'hostname'
  - 'domain'
values: 'My organisation name'
evtInfos: 'OSINT'  
orgs:
tags:
normalKey: 'My Splunk Key'
alertKey: 'My Splunk Alert Key'
trigger: False
url: 'My Splunk URL'
```

# Dependencies

* [Argparse](https://pypi.org/project/argparse/)
* [ZeroMQ](https://zeromq.org/languages/python/)
* [Pprint](https://docs.python.org/3/library/pprint.html)
* [Requests](https://pypi.org/project/requests/)
* [PyYAML](https://pypi.org/project/PyYAML/)