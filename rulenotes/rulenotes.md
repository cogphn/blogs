
### Simple/ atomic

 - simple, query-based evaluation  
 - all relevant attributes are available in a single observation/ event
 - 

 - example implementation
~~~kql
Event 
| where EventID == 1 and EventData contains "svchost"
~~~


### Threshold 

- aggregate query
- checks for the frequency of an occurance over a pre-defined period of time 


- example implementation
~~~kql
Event
| where TimeGenerated between (ago(10m) .. now() ) and EventID ==1
| summarize count() by Computer
| where count_ > 10
~~~

### Sequence 

- sequence query 
- where a number of different events occur in a specific sequence

- example implementation 
~~~kql
Event
| where TimeGenerated between (ago(10m) .. now() )
| where EventID == 1 
| project EventID, tg1=TimeGenerated, Computer, EventData
| join kind=inner ( Event | where EventID ==5  | project EventID, tg2=TimeGenerated, Computer, EventData) on $left.Computer == $right.Computer
| where tg2 > tg1
~~~


### Anomaly 

 - unusual events relative to an defined/ calculated baseline 
 - commonly implemented with ML algorithms, but aggregate queries can be developed for a similar effect


 - example implemnentation
~~~kql
// check for process names that did not occur in a predefined window
let procs = view() { Event | where EventID == 1 and TimeGenerated between (ago(5h) .. ago(1h) ) | extend procinfo=parse_xml(EventData).DataItem.EventData.Data[4]|  summarize by tostring(procinfo)  };
Event
| where EventID ==1 and TimeGenerated between (ago(1h) .. now() )
| extend procinfo_new=tostring(parse_xml(EventData).DataItem.EventData.Data[4])
| project TimeGenerated, Computer, procinfo_new
| join kind=leftouter (procs ) on $left.procinfo_new == $right.procinfo
| where isempty(procinfo)
~~~





### Composite 
 - one or more rules were matched
 - can be restricted by attribute (for eg. the asset)
 - can be implemented as an incident creation rule in MS Sentinel

