from thehive import TheHiveConnector
import json, requests, time

def createTime(days=1):
    """
    Method to extract the time from days ago.
    """
    return (int(round(time.time() * 1000))-(days*24*60*60*1000))
payload={"query":[{"_name":"listAlert"},{"_name":"filter","_and":[{"_lt":{"_createdAt":createTime(days=90)}},{"_field":"imported","_value":False}]}]}
payload=json.dumps(payload)
url='http://10.33.16.151:9000/api/v1/query?name=alerts'
headers={'Authorization': 'Bearer +k4fIR4kAcf7Zkcp0ReM+xcvE8p5FSoz', 'Content-Type': 'application/json'}
alerts=json.loads(requests.post(url, headers=headers, data=payload).text)
#alerts = TheHiveConnector.getAlert(time=createTime(days=90))
for alert in alerts:
    #print(alert)
    #print()
    TheHiveConnector.deleteAlert(alert['_id'])
'''
    if count >2000:
        try:
            if alert['case']:
                count+=1
                pass

        except:
            hive.deleteAlert(alert['id'])
            print("deleted Alert: "+alert['title'])
            count+=1
    else:
        count+=1
    '''
