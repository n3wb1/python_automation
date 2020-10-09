![](../../images/thehive.png)
# **theHive Python Documentation**

## *Authentication*
* There are 2 types of Authentication for theHive in this library. There is authentication for both GET and POST requests but they both require the same API token.
* The API token needs to be inserted as:
```python
{'Authorization': 'Bearer  <APIToken Here>'}
```
* For POST requests, you will need to add
```python
{'Authorization': 'Bearer  <APIToken Here>', 'Content-Type': 'application/json'}
```
to the headers.

## *Methods*
Below is a list of all methods and their description
#### GET:
* *getAlert(**kwargs)*:
    * returns a


* *getCaseArtifact(caseId)*:
    *


* *getCase(**kwargs)*:
    *


* *getCaseTasks(caseId)*:
    *

* *getTask(taskId)*:
    *


* *getTaskLogs(taskId)*:
    *


* *getJob(jobId)*:
    *   


#### POST:

  * *createAlert(**kwargs)*:
    *

  * *createTask(id, **kwargs)*:
    *

#### PATCH:

  * *updateAlert(id, **kwargs)*:
    *
