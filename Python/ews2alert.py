#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os, sys, json
import logging, time, datetime, threading
import eml_parser, threading

if not os.path.exists("logs"):
    os.makedirs("logs")
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%a, %d %b %Y %H:%M:%S', filename='logs/ews2alert.log', filemode='w')

from synapse.common import getConf
from synapse.objects.EwsConnector import EwsConnector
from synapse.objects.TheHiveConnector import TheHiveConnector
from synapse.objects.TempAttachment import TempAttachment
from cortex import CortexConnector

def parseEmail(email, theHiveConnector):
    #prepping alert details
    conversationId = email.conversation_id.id
    alertTitle = str(email.subject)
    alertDescription = ('```\n' +
        'Alert created by Synapse\n' +
        'conversation_id: "' +
        str(email.conversation_id.id) +
        '"\n' +
        '```')
    alertTags=['Classification:Event']
    #iterate through all files and attachments (including the email file itself)
    for msg in email.attachments:
        try:
            q = dict()
            q['sourceRef'] = str(conversationId)
            esAlertId = theHiveConnector.findAlert(q)
            tempAttachment = TempAttachment(msg)
            #running the eml analyzer in cortex
            if not tempAttachment.isInline:
                tmpFilepath = tempAttachment.writeFile()
                if tmpFilepath.endswith('.eml'):
                    job = (CortexConnector.api.analyzers.run_by_name('EmlParser_1_2', {
                        'data': tmpFilepath,
                        'dataType':'file',
                        'tlp':1
                    }, force=1)).json()
                    while job['status']!='Success' and  job['status'] != 'Failure':
                        job = CortexConnector.getJob(job['id'])
                        time.sleep(2)
                        #print(json.dumps(job, indent=2))
                    headers = '## Headers\n' +'```\n' +job['report']['full']['headers']+'```\n'
                    body = '## Body\n' +'```\n' +job['report']['full']['body']+'```\n'
                    alertDescription = headers + body + alertDescription
                    with open(tmpFilepath, 'rb') as fhdl:
                        raw_email = fhdl.read()
                        parsed_eml = eml_parser.eml_parser.decode_email_b(raw_email)
                    alertArtifacts = createArtifacts(parsed_eml, theHiveConnector, tmpFilepath)
                    alert = theHiveConnector.craftAlert(alertTitle, alertDescription, severity=2, tlp=2, status="New", date=(int(time.time()*1000)), tags=alertTags, type="Phishing", source="Phishing Mailbox", sourceRef=email.conversation_id.id, artifacts=alertArtifacts, caseTemplate='')
                    theHiveEsAlertId = theHiveConnector.createAlert(alert)['id']

        except Exception as e:
             logger.error('Failed to create alert from email', exc_info=True)
             #commenting out until flask is implemented
             #report['success'] = False
             #return report

def createArtifacts(parsed_eml, theHiveConnector, tmpFilepath):
    #formatting and prepping observables for theHive
    alertArtifacts=[]
    alertArtifacts.append(theHiveConnector.craftAlertArtifact(dataType='file', message="Phishing Email", data=tmpFilepath, tags=['src:Synapse']))
    alertArtifacts.append(theHiveConnector.craftAlertArtifact(dataType='mail_subject', message="Phishing Email Subject", data=parsed_eml['header']['subject'], tags=['src:Synapse']))
    try:
        if 'message-id' in parsed_eml['header']['header']:
            alertArtifacts.append(theHiveConnector.craftAlertArtifact(dataType='other', message="Message Id", data=parsed_eml['header']['header']['message-id'][0], tags=['src:Synapse']))
    except:
        logger.error('Failed to create artifact from email', exc_info=True)
    try:
        for i in parsed_eml['header']['received_ip']:
            alertArtifacts.append(theHiveConnector.craftAlertArtifact(dataType='src_ip', message="Source IP", data=i, tags=['src:Synapse']))
    except:
        logger.error('Failed to create artifact from email', exc_info=True)
    try:
        for i in parsed_eml['header']['to']:
            alertArtifacts.append(theHiveConnector.craftAlertArtifact(dataType='mail', message="Recipients", data=i, tags=['src:Synapse']))
    except:
        logger.error('Failed to create artifact from email', exc_info=True)
    try:
        for i in parsed_eml['header']['header']['return-path']:
            alertArtifacts.append(theHiveConnector.craftAlertArtifact(dataType='mail', message="Return Path", data=i, tags=['src:Synapse']))
    except:
        logger.error('Failed to create artifact from email', exc_info=True)
    try:
        if 'x-originating-ip' in parsed_eml['header']['header']:
            alertArtifacts.append(theHiveConnector.craftAlertArtifact(dataType='mail', message="Origin IP", data=parsed_eml['header']['header']['x-originating-ip'], tags=['src:Synapse']))
    except:
        logger.error('Failed to create artifact from email', exc_info=True)
    return alertArtifacts

def connectEwsAlert():
    #setting up logging
    logger = logging.getLogger(__name__)
    logger.info('%s.connectEws starts', __name__)
    report = dict()
    report['success'] = bool()
    # grabbing configurations for EWS and theHive
    cfg = getConf()
    ewsConnector = EwsConnector(cfg)
    theHiveConnector = TheHiveConnector(cfg)
    folder_name = cfg.get('EWS', 'folder_name')
    #exctracting emails from EWS
    unread = ewsConnector.scan(folder_name)
    threads = []
    #iterating/parsing through all unread emails and marking them as read
    for email in unread:
        parseEmail(email, theHiveConnector)
        ewsConnector.markAsRead(email)
        #threads.append[parse_thread]

if __name__ == '__main__':
    connectEwsAlert()
