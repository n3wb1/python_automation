#!/usr/bin/env python3
# -*- coding: utf-8 -*
from .connector import SentinelOne
from .config import url, token

SentinelOneConnector=SentinelOne(config.url, config.token)
