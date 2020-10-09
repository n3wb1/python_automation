#!/usr/bin/env python3
# -*- coding: utf-8 -*
#__init__ for theHive package
from .connector import TheHive
from .config import url, token

TheHiveConnector=TheHive(config.url, config.token)
