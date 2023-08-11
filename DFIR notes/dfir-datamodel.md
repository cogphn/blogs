# Building a forensic data ... data ( :/ ) model



## The problem with timestamps

I've seen some systems organize data by artifact. So a single AmCache entry has multiple timestamps, same with NTFS file entries. kool potatoes. You can store this data like so:

| Attribute 2 | Timestamp 1 | Timestamp 2 | Timestamp 3 |
| :--- | :--- | :--- | :-- |
| attribute a | value1 b | 2023-01-02 00:03:00 | 2021-02-03 00:01:43 | 2023-01-02 00:00:32 |

Let's say for example we're dealing with an event that occured in January 2023. Clearly one of these timestamps is not like the others. This timestamp of course has value,  but not for directly explaining what happened during January 2023.

Its much more convenient for analysts to treat each timestamp as a separate event because in reality it is. For example:

| EntryNumber | Filename | Directory | FN Created | FN Modified | FN Accessed | 
| :--- | :--- | :--- | :--- | :--- | :--- |
| 201 | Somefile.txt | C:\users\bobdoe\Desktop\ | 2023-02-01 00:00:00 | 2023-02-01 00:05:00 | 2023-02-01 01:03:13

While this is a single record from the data source, it's representing 3 events that impacted the same file. For the file system it makes sense to track this metadata with the file itself, but for analysis, we have to treat each timestamp as a separate event.

For analysts, this data is makes more sense when ordered sequentially, by timestamp.

| EntryNumber | Filename | Directry  | Timestamp | Event type |
| ---: | :--- | :--- | ---: | :--- |
| 201 | Somefile.txt | C:\users\bobdoe\Desktop\ | 2023-02-01 00:00:00 | FN Created
| 201 | Somefile.txt | C:\users\bobdoe\Desktop\ | 2023-02-01 00:05:00 | FN Modified
| 201 | Somefile.txt | C:\users\bobdoe\Desktop\ | 2023-02-01 01:03:13 | FN Accessed 



## Artifacts 

The Velociraptor project has a handy artifact reference that shows details for numerous artifacts [Artifact Refence :: Velociraptor - Digging Deeper!](https://docs.velociraptor.app/artifact_references/)

