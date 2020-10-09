#!/usr/bin/env python3
# -*- coding: utf-8 -*

import sys, json, requests, datetime, time
from thehive import query
'''
TH_API_GET_ENDPOINTS: Dict[str, str] = {
    "alert": "/api/alert",
    "alert_search": "/api/alert/_search?range_all"
    "artifact": "/api/case/artifact/_search?range_all"
    "case": "/api/case",
    "job": "/api/connector/cortex/job/",
    "log": "/api/case/task/",
    "task": "/api/case/task/",
}
'''
class TheHive:
    """
        Python API for theHive

    """
    def __init__(self, url, token):
        self.url = url
        self.headers={'Authorization': 'Bearer '+token}
        self.post_header={'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'}
        #self.api_endpoints = TH_API_ENDPOINTS

    def _get(self, type, query=''):
        """
            Private method to send GET requests and parse the Response
        """
        if type=='job':
            request = self.url+'/api/connector/cortex/job/'+query

        if type=='task':
            request = self.url+'/api/case/task/'+query

        if type=='case':
            request = self.url+'/api/case'+query+'?range=all'

        if type=='alert':
            request = self.url+'/api/alert'+query+"?range=all"

        if type=='log':
            request = self.url+'/api/case/task/'+query+'/log'

        return json.loads(requests.get(request, headers=self.headers).text)

    def _post(self, type, payload, query=''):
        """
            Private method to send POST requests and parse the Response
        """
        if type=='alert':
            request = self.url+'/api/alert'+query

        if type=='alert_search':
            request = self.url+'/api/alert/_search?range_all'

        if type=='artifact':
            request = self.url+'/api/case/artifact/_search?range_all'

        if type=='case':
            request = self.url+'/api/case'

        if type=='task_search':
            request = self.url+'/api/case/task/_search'

        if type=="job":
            request = self.url+'/api/connector/cortex/job'

        response = json.loads(requests.post(request, headers=self.post_header, data=payload).text)
        return response


    def _patch(self, type, payload, id):
        """
            Private method to send POST requests and parse the Response
        """
        if type=='alert':
            request = self.url+'/api/alert/'+id

        response = json.loads(requests.patch(request, headers=self.post_header, data=payload, verify=False).text)
        return response

    def _delete(self, type, id):
        """
            Private method to send DELETE requests and parse the Response
        """
        if type=='alert':
            request = self.url+'/api/alert/'+id+'?force=1'

        response = requests.delete(request, headers=self.post_header, verify=False).text
        return response

    def _createQuery(self, arg, url=''):
        #query Construction
        for key, value in arg.items():
            url+='&{0}={1}'.format(key, value)
        return url

    def getAlert(self, alertId=None, time=None, sourceRef=None):
        """
            Method to obtain an Alert in theHive
            :param id: String for the unique id for an Alert
        """
        if not alertId and not time and not sourceRef:
            return self._get('alert')

        elif not alertId and not sourceRef:
            payload={'range':'all', 'query': {"_lte":{"_field": "createdAt", "_value":time}}}
            return self._post('alert_search', json.dumps(payload))
            #return self._get('alert', query='?createdAt<='+str(time))

        elif not alertId and not time:
            payload={'range':'all', 'query': query.Eq('sourceRef', sourceRef)}
            return self._post('alert_search', json.dumps(payload))

        return self._get('alert', query="/"+alertId)

    def createAlert(self, **kwargs):
        """
            Method to create an alert in theHive
            See sentinelone_alert_creation.py as an example of the parameters needed to create an alert.
        """
        payload = json.dumps(kwargs)
        response = self._post('alert', payload)
        return response

    def updateAlert(self, id, **kwargs):
        """
            Method to update an alert in theHive
            See sentinelone_alert_creation.py as an example of the parameters needed to create an alert.
        """
        payload = json.dumps(kwargs)
        response = self._patch('alert', payload, id)
        return response

    def deleteAlert(self, alertId):
        response = self._delete('alert', alertId)
        return response

    def getCaseArtifact(self, caseId):
        payload={
            "query" : { "_parent": { "_type": "case", "_query": { "_id" : caseId } } },
            "range" : "all"
            }
        return self._post('artifact', json.dumps(payload))

    def getCase(self, caseId=None):
        """
            Method to obtain a case in theHive
            :param caseId: String for the name of the case Title
        """
        if not caseId:
            return self._get('case')
        return self._get('case', query="/"+caseId)

    def createCase(self, case_title, **kwargs):
        """
            Method to create a case in theHive
            :param case_title: String for the name of the case Title
        """
        date=str(datetime.date.today()).replace('-','')
        kwargs['title']=date+' '+case_title
        payload = json.dumps(kwargs)
        response = self._post('case', payload)

    def getCaseTasks(self, caseId):
        """
            Method to search for a task with optional filters in theHive
        """
        list={"query":{"_parent":{"_type": "case", "_id": caseId}}}
        payload = json.dumps(list)
        return self._post('task_search', payload)

    def getTask(self, taskId):
        """
            Method to get task in theHive
        """
        return self._get('task', taskId)

#FIXME:CreateTask. #20190604 #createTask()
    def createTask(self, id, **kwargs):
        """
            Method to create a task within a case in theHive
            :param case_id: String for the id of the case the task will be added to
        """
        payload = json.dumps(kwargs)
        response = self._post('case', payload, id)

    def getTaskLogs(self, taskId):
        """
            Method to get task in theHive
        """
        return self._get('log', taskId)

    def getJob(self, jobId):
        """
            Method to obtain the report of completed job task
            :return: The JSON file of either the full report or the observables produced by an Analyzer job
            :rtype: json file
        """
        report = self._get('job', jobId)['report']
        return report

    def createJob(self, analyzerId, artifactId):

        payload=json.dumps({'analyzerId':analyzerId, 'cortexId':'CORTEX-SERVER-ID', 'artifactId':artifactId})
        response=self._post("job", payload)
        return response
#IDEA: Create a package or SDK for Responders. #20190425 #SDK
