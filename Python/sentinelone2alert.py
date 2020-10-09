#!/usr/bin/env python3
# -*- coding: utf-8 -*
from sentinelone import SentinelOneConnector
from thehive import TheHiveConnector
from markdownify import markdownify as md
import sys, json, requests, datetime, time

#initializing methods

def createTime(minutes=10):
    """
    Method to extract the time from minutes ago.
    """
    return (int(round(time.time() * 1000))-(minutes*60*1000))


def addAgentArtifact(agent, threat):
    """
    Method to extract artifacts from the threat and agent attributes to add to theTheHiveConnector
    """
    list=[]
    for ip in agent['networkInterfaces'][0]['inet']:
        list.append({'dataType': 'ip', 'data': ip, 'message': 'SentinelOne'})
    if threat['username']!="":
        list.append({'dataType': 'username', 'data': threat['username'], 'message': 'SentinelOne'})
    list.append({'dataType': 'hostname', 'data': agent['computerName'], 'message': 'SentinelOne'})
    if agent['domain']!="":
        list.append({'dataType': 'domain', 'data': agent['domain'], 'message': 'SentinelOne'})
    #os_info=agent['osName']+' '+agent['osArch']+' '+agent['osRevision']
    #list.append({'dataType': 'os_info', 'data': agent['osType'], 'message': 'SentinelOne'})
    list.append({'dataType': 'hash', 'data': threat['fileContentHash'], 'message': 'SentinelOne'})
    if threat['fileDisplayName']!="":
        list.append({'dataType': 'filename', 'data': threat['fileDisplayName'], 'message': 'SentinelOne'})
    list.append({'dataType': 'other', 'data': threat['maliciousGroupId'], 'message': 'SentinelOne MaliciousGroupId'})
    return list

def findIOC(iocs, list):
    description="\n***\nIndicators:"
    for id in list:
        for ioc in iocs:
            if id==ioc['id']:
                try:
                    des=md(ioc['description'])
                    description+="\n\t* "+des
                    break
                except:
                    description+="\n\t* "+ioc['description']
                    break
    return description

def alertCreation(threat, iocs):
    #grabbing the agent and indicator details
    flag=1
    agent=SentinelOneConnector.getAgents(ids=threat['agentId'])[0]
    indicators=findIOC(iocs, threat['indicators'])
    rep="N/A"
    if threat['fileContentHash']:
        rep = SentinelOneConnector.getReputation(threat['fileContentHash'])
    #setting up the tags
    tags=['Classification:Event', 'Malware:'+threat['classification'], 'os:'+agent['osType']]
    titleBegin = 'Active'
    severity=3
    if threat['mitigationStatus']=="active":
        severity=3
    elif threat['mitigationStatus']=="suspicious":
        titleBegin = 'Suspcious'
        severity=2
    #elif threat['mitigationStatus']=="suspicious_resolved":
    #    titleBegin = 'Suspicious'
    #    severity=2
    #    tags.append("Resolved")
    elif threat['mitigationStatus']=="mitigated":# and SentinelOneConnector.getReputation(threat['fileContentHash'])>5:
        titleBegin = 'Mitigated'
        severity=2
        tags.append("Status:Resolved")
    else:
        flag=0
        titleBegin = 'Mitigated'
        severity=1
        tags.append("Status:Resolved")
    #creating threat link, title, artifacts, and summary based on the threat details
    if flag==1:
        #link="[Link](https://maximus.sentinelone.net/analyze/threats/"+str(threat['id'])+"/overview)"
        title='S1 '+titleBegin+' Threat - '+threat['fileDisplayName']+' on '+agent['computerName']
        artifacts=addAgentArtifact(agent, threat)
        summary = str('\n***\n' +
            '## Summary\n' +
            '|                         |               |\n' +
            '| ----------------------- | ------------- |\n' +
            #'| **Link to Threat**      | ' + link + ' |\n' +
            '| **Site**                | ' + threat['siteName'] + ' |\n' +
            '| **Domain**              | ' + agent['domain'] + ' |\n' +
            '| **Group**               | ' + agent['groupName'] + ' |\n' +
            '| **Machine Name**        | ' + agent['computerName'] + ' |\n' +
            '| **Machine Type**        | ' + agent['machineType'] + ' |\n' +
            '| **Agent Version**       | ' + threat['agentVersion'] + ' |\n' +
            '| **Initiated By**        | ' + threat['initiatedBy'] + ' |\n' +
            '| **Engine Detection**    | ' + str(threat['engines']) + ' |\n' +
            '| **Hash Classification**    | ' + str(rep) + ' |\n' +
            '| **Threat Kill**         | ' + str(threat['mitigationReport']['kill']['status']) + ' |\n' +
            '| **Threat Quarantine**   | ' + str(threat['mitigationReport']['quarantine']['status']) +' |\n***\n')
        #Creating an alert for TheHiveConnector using the SentinelOne threat data
        response=TheHiveConnector.createAlert(
                                title=title,
                                tags=tags,
                                description=str(threat['description']+summary+indicators),
                                type='Malicious Code/Malware',
                                source='SentinelOne',
                                artifacts=artifacts,
                                sourceRef=threat['id'],
                                severity=severity,
                                externalLink="https://maximus.sentinelone.net/analyze/threats/"+str(threat['id'])+"/overview"
                                )
        print(response)

def run():
    #Obtain all threats from the past 24 hours from SentinelOne
    threatsActive=SentinelOneConnector.getThreats(mitigationStatuses="active", resolved=False, createdAt__gt=createTime())
    threatsSuspcious=SentinelOneConnector.getThreats(mitigationStatuses="suspicious", createdAt__gt=createTime())
    #threatsMitigated=s1c.getThreats(mitigationStatuses="mitigated", createdAt__gt=createTime())
    threats=threatsActive+threatsSuspcious
    #get all indicators from sentinelone
    iocs = SentinelOneConnector.getIoc()
    for threat in threats:
        try:
            alertCreation(threat, iocs)
        except:
            pass

if __name__=='__main__':
     run()
