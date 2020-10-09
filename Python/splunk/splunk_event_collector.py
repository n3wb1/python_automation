#!/usr/bin/env python3
# -*- coding: utf-8 -*

import sys, json, requests, datetime, time

class Splunk_Event_Collector:
    """
        Python API for Splunk Event Collector

    """
    def __init__(self):

        self.url = ""
        self.headers = {"Authorization": ""}
        self.session = session=requests.Session()
        self.host = 
    def _post(self, event, type):
        """
            Private method to send POST requests and parse the Response
        """
        data={
            "host": self.host,
            "source" : "thehive",
            "event": event
        }

        if type=='artifact':
            data["sourcetype"]="thehive_artifact"

        if type=='case':
            data["sourcetype"]="thehive_case"

        if type=='alert':
            data["sourcetype"]="thehive_alert"

        return requests.post(url=self.url, headers=self.headers, json=data).text

    def add_event(self, event, type):
        self._post(event, type)
