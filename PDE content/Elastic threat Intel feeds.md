To work with threat intelligence feeds, we need to make some modifications to our Elastic stack. Once set up, a Filebeat process will download indicators from threat intelligence sources, and send them to an index in our Elastic stack.

The first step we need to complete is the installation of Filebeat. Filebeat is available for multiple platforms. You can find the installation instructions for your platform from the Filebeat download page here:

https://www.elastic.co/downloads/beats/filebeat

The installation process creates a number of files in /etc/filebeat/ (“c:\Program Files\Elastic\Beats\” for Windows users). We will need to make modifications to two files in this directory, specifically filebeat.yml and modules.d/threatintel.yml. 

Next we need to configure Filebeat. First we need to modify filebeat.yml. The important sections to fill in are the Kibana sections, specifically setup.kibana.host, and the elastic section. 



