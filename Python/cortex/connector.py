#!/usr/bin/env python3
# -*- coding: utf-8 -*

import sys, json, requests, datetime, time
from cortex4py.api import Api
from cortex4py.query import *

class Cortex:
    """
        Python API for Cortex

    """
    def __init__(self, url, token):
        self.url = url+'/api/'
        self.headers={'Authorization': 'Bearer '+token}
        self.post_header={'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'}
        self.api = Api(url, token)

    def _get(self, type, query=''):
        """
            Private method to send GET requests and parse the Response
        """
        if type=='job':
            request = self.url+'job/'+query+'/report'

            #response = requests.get(self.url+'job/'query, headers=self.headers).text

        if type=='analyzer':
            request = self.url+'job/_search'+query

        return json.loads(requests.get(request, headers=self.headers).text)

    def _post(self, type, id, file, payload):
        """
            Private method to send POST requests and parse the Response
        """
        if type=='analyzer':
            request = self.url+'analyzer/'+id+'/run/'

        return json.loads(requests.get(request, headers=self.headers, data=payload, files=file).text)

    def getJob(self, jobId):
        """
            :param id: String value of unique job identified
            :return: The JSON file of either the full report or the observables produced by an Analyzer job
            :rtype: json file
        """
        report = self._get('job', query=jobId)
        return report

#FIXME: run job for file attachments. #20190604 #runJob
    def runJob(self, analyzerName, data, dataType, **kwargs):
        payload = json.dumps(kwargs)
        job = cortex.api.analyzers.run_by_name(analyzerName, {'data':data,'dataType':dataType, 'tlp':1}, force=1)
        return json.dumps(job.json())
# TODO: Implements Cortex API functionality. #20190425 #API
