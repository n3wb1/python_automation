#!/usr/bin/env python3
# -*- coding: utf-8 -*

import json, requests, time

class SentinelOne:
    """
        Python API for Maximus SentinelOne Cloud Console

    """
    def __init__(self, url, token):
        self.url = url
        self.headers =  {'Content-Type': 'application/json', 'Authorization': 'APIToken '+token}
        self.session = session=requests.Session()

    def _get(self, type, query=''):
        """
            Private method to send GET requests and parse the Response
        """
        if type == 'agents':
            request = self.url+'/agents?limit=1000'+query
            response = json.loads(self.session.get(request, headers=self.headers, verify=False).text)

            agents = self._iterate(request, response['data'], response['pagination']['nextCursor'])
            return agents

        if type == 'threats':
            request = self.url+'/threats?limit=1000'+query
            response = json.loads(self.session.get(request, headers=self.headers, verify=False).text)
            print(response)
            threats = self._iterate(request, response['data'], response['pagination']['nextCursor'])
            return threats

        if type == 'ioc':
            request = self.url+'/threats/static-indicators'
            response = json.loads(self.session.get(request, headers=self.headers, verify=False).text)
            return response['data']['indicators']

        if type == 'groupedThreats':
            request = self.url+'/private/threat-groups?limit=1000'+query
            response = json.loads(self.session.get(request, headers=self.headers, verify=False).text)
            groupedThreats = self._iterate(request, response['data'], response['pagination']['nextCursor'])
            return groupedThreats

        if type == 'reputation':
            request = self.url+'/hashes/'+query+'/reputation'
            reputation = json.loads(self.session.get(request, headers=self.headers, verify=False).text)['data']['rank']
            return reputation
        # TODO: Create GET for blacklisted items. #20190425 #GET
        #if type == 'blacklist':

    def _post(self, type, payload):
        """
            Private method to send POST requests and parse the Response
        """
        if type == 'blacklist':
            request = self.url+'/threats/add-to-blacklist'
            response = self.session.post(request, headers=self.headers, data=payload, verify=False).text
            return response
        if type == 'resolved':
            request = self.url+'/threats/mark-as-resolved'
            response = self.session.post(request, headers=self.headers, data=payload, verify=False).text
            return response
        if type == 'reject':
            request = self.url+'/agents/actions/reject-uninstall'
            response = self.session.post(request, headers=self.headers, data=payload, verify=False).text
            return response
        if type == 'api':
            request = self.url+'/users/generate-api-token'
            response = self.session.post(request, headers=self.headers, verify=False).text
            return response

    def _iterate(self, request, list, cursor):
        if cursor is not None:
            response = json.loads(self.session.get(request+'&cursor='+cursor, headers=self.headers, verify=False).text)
            for i in response['data']:
                list.append(i)
            return self._iterate(request, list, response['pagination']['nextCursor'])
        return list

    def _createQuery(self, arg, url=''):
        #query Construction
        for key, value in arg.items():
            url+='&{0}={1}'.format(key, value)
        return url

    def getAgents(self, **kwargs):
        """
            :return: The JSON file of all agents in the cloud console
            :rtype: json file
        """
        if not kwargs:
            return self._get('agents')
        query=self._createQuery(kwargs)
        return self._get('agents', query=query)

    def getThreats(self, **kwargs):
        """
            Method to retrieve all threats from SentinelOne
            :param: kwargs - the parameters to filter the threats
            :return: The JSON file of all threats in the cloud console
            :rtype: JSON
        """
        if not kwargs:
            return self._get('threats')

        query=self._createQuery(kwargs)
        return self._get('threats', query=query)

# FIXME: getBlackItems. #20190425 #GET
    def getBlackItems(self, **kwargs):
        """
            :
        """
        if not kwargs:
            return self._get('blacklist')

        query=self._createQuery(kwargs)
        return self._get('blacklist', query=query)

    def markResolved(self):
        """
            Method to resolve all threats marked as mitigated and blocked from SentinelOne
            :rtype: JSON
        """
        payload={"filter":{"mitigationStatuses":["mitigated", "blocked"], "resolved":False}}
        return self._post("resolved", json.dumps(payload))

    def uninstallReject(self):
        """
            Method to reject all uninstall requests in SentinelOne
            :rtype: JSON
        """
        payload={'filter':{'isPendingUninstall':True}}
        return self._post("reject", json.dumps(payload))

    def generateToken(self):
        """
            Method regenerate a new api token
            :rtype: JSON
        """
        return self._post("api", "")

    def getIoc(self):
        """
            Method to retrieve all static indicators of threats
        """
        return self._get("ioc")

    def getGroupThreats(self, **kwargs):

        if not kwargs:
            return self._get('groupedThreats')

        query=self._createQuery(kwargs)
        return self._get('groupedThreats', query=query)

    def getReputation(self, hash):
        reputation=self._get('reputation', query=hash)
        if reputation!=None:
            return reputation
        else:
            return 0
