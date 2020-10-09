#!/usr/bin/env python3
# -*- coding: utf-8 -*

from thehive import TheHiveConnector
from splunk import splunk_event_collector
import sys, json, requests, datetime, time

splunk=splunk_event_collector.Splunk_Event_Collector()

#retrieve all case information from theHive
cases = TheHiveConnector.getCase()

#iterate through each case
for case in cases:
    #change the caseId to caseNumber for more clarity
    case['caseNumber'] = case.pop('caseId')
    case['routing'] = case['_routing']
    case.pop('description')
    #add the case as an event into splunk
    splunk.add_event(case, 'case')
    #add all the artifacts from the case into splunk
    #for artifact in hive.getCaseArtifact(case['id']):
        #artifact['routing'] = artifact['_routing']
        #artifact['parent'] = artifact['_parent']
        #splunk.add_event(artifact, 'artifact')
