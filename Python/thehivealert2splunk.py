#!/usr/bin/env python3
# -*- coding: utf-8 -*

from thehive import theHiveConnector
from splunk import splunk_event_collector
import sys, json, requests, datetime, time

#method to create epoch time based on hours
def createTime(hours=1):
    """
    Method to extract the time from hours ago.
    """
    return str(int(round(time.time() * 1000))-(hours*60*60*1000))
#intiate connection to Splunk
splunk=splunk_event_collector.Splunk_Event_Collector()

for alert in theHiveConnector.getAlert(time=createTime(hours=168)):
    alert['routing'] = alert['_routing']
    alert['parent'] = alert['_parent']
    splunk.add_event(alert, 'alert')
    artifacts=alert['artifacts']
    for artifact in artifacts:
        artifact['alertId']=alert['id']
        splunk.add_event(artifact, 'artifact')
        print(json.dumps(artifact, indent=4, sort_keys=True))
