# CloudGenix Get Events (Preview)
This utility is used to download events from the CloudGenix managed network to a CSV file.

#### Synopsis
Enables downloading of alarms and alerts raised on the CloudGenix managed network. The user can filter events by Site, event codes and based on the start time. Numhours is set to 3 by default. To retrieve events from a specific time range, use the keyword RANGE. See usage examples below.


#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.1.1b1 - <https://github.com/CloudGenix/sdk-python>
    * CloudGenix ID-Name Utility >= 2.0.1 - <https://github.com/ebob9/cloudgenix-idname>
* ProgressBar2

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `getevents.py`. 

### Examples of usage:
Get events from a site (past 3 hours):
```
./getevents.py -S Sitename 
```
Get events from a site for the past 24 hours:
```
./getevents.py -S Sitename -H 24 
```
Get events from a site for a specific time range:
```
./getevents.py -S Sitename -H RANGE -ST 2022-08-01T00:00:00Z -ET 2022-08-02T00:00:00Z
```
Get events from a multiple sites (past 3 hours):
``` 
./getevents.py -S Site1,Site2,Site3
```
Get events for specific event codes (past 3 hours):
```angular2
./getevents.py -EC NETWORK_VPNLINK_DOWN,NETWORK_DIRECTINTERNET_DOWN
```


Use the -H hours to specify the time delta in hours for the event query.

Help Text:
```angular2
Tanushrees-MacBook-Pro:getevents tanushreekamath$ ./getevents.py -h
usage: getevents.py [-h] [--controller CONTROLLER] [--email EMAIL]
                    [--pass PASS] [--eventcodes EVENTCODES]
                    [--sitename SITENAME] [--hour HOUR]
                    [--starttime STARTTIME] [--endtime ENDTIME]

CloudGenix: Get Events Script.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod:
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

Filters for events:
  The following attributes will be used to query events

  --eventcodes EVENTCODES, -EC EVENTCODES
                        List event codes you want to query for
  --sitename SITENAME, -S SITENAME
                        Name of the Site you want events filtered for. For
                        multiple sites, separate names by using a comma.
  --hour HOUR, -H HOUR  Number of hours from now you need the events queried
                        for. Or use the keyword RANGE to provide a time range
  --starttime STARTTIME, -ST STARTTIME
                        Start time in format YYYY-MM-DDTHH:MM:SSZ
  --endtime ENDTIME, -ET ENDTIME
                        End time in format YYYY-MM-DDTHH:MM:SSZ
```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b8** | Numhours set to 3 hours. Updated README with examples for time range |
| **1.0.0** | **b7** | Minor bug fixes. |
| **1.0.0** | **b6** | Minor bug fixes.|
| **1.0.0** | **b5** | Included idname utility. Made edits to include VPN link name in info.|
| **1.0.0** | **b4** | Minor bug fixes. Acknowledgment info now lists username and email.|
| **1.0.0** | **b3** | Minor bug fixes.|
| **1.0.0** | **b2** | Added support for time range. Fixed minor bug.|
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SDWAN Documentation at <https://docs.paloaltonetworks.com/prisma/prisma-sd-wan>
 
