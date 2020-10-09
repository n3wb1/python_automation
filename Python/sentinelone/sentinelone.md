![](../../images/sentinelone.png)
# **SentinelOne Python Documentation**

## *Authentication*
* Authentication requires an API token to be inserted in the headers:
```python
{'Content-Type': 'application/json', 'Authorization': 'APIToken <APIToken Here>'}
```

## *Methods*
Below is a list of all methods and their description
#### GET:
* *getAgents(**kwargs)*:
    * returns a list of all agents. Parameters can be specified to filter results based on Sentinel API documentation.


* *getThreats(**kwargs)*:
    * returns a list of all threats. Parameters can be specified to filter results based on Sentinel API documentation.


* *getGroupThreats(**kwargs)*:
    * returns a list of all threats that are grouped together by hash classification. Parameters can be specified to filter results based on Sentinel API documentation.


* *getIoc()*:
    * returns a list MITRE IOCs and the corresponding SentinelOne IDs for mapping.


* *getReputation(hash)*:
    * returns the reputation score of a file hash

#### POST:
  * markResolved():
    * method to Resolve all Threats that are classified as "Mitigated" or "Blocked"


  * uninstallReject():
    * method to reject all uninstall requests.
