# DDoSia

```
▓█████▄ ▓█████▄  ▒█████    ██████  ██▓ ▄▄▄      
▒██▀ ██▌▒██▀ ██▌▒██▒  ██▒▒██    ▒ ▓██▒▒████▄    
░██   █▌░██   █▌▒██░  ██▒░ ▓██▄   ▒██▒▒██  ▀█▄  
░▓█▄   ▌░▓█▄   ▌▒██   ██░  ▒   ██▒░██░░██▄▄▄▄██ 
░▒████▓ ░▒████▓ ░ ████▓▒░▒██████▒▒░██░ ▓█   ▓██▒
 ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓   ▒▒   ▓▒█░
 ░ ▒  ▒  ░ ▒  ▒   ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░  ▒   ▒▒ ░
 ░ ░  ░  ░ ░  ░ ░ ░ ░ ▒  ░  ░  ░   ▒ ░  ░   ▒   
   ░       ░        ░ ░        ░   ░        ░  ░
 ░       ░                                      
```


DDoSia is a participatory distributed denial of service (DDoS) tool. Instead of leveraging a botnet of compromised systems, DDoSia recruits individuals of voluntarily run their DDoS client, which receives tasking from a central service. Operated by NoName057(16), DDoSia was heavily used for DDoS attacks against Ukraine, NATO and European countries. 

This repository contains archives of DDoSia attacks issued from those central control servers from 2023 until the law enforcement disruption in 2025.

## Reporting:
* https://therecord.media/ddosia-pro-russian-hackers-upgrades
* https://www.recordedfuture.com/research/anatomy-of-ddosia
* https://euneighbourseast.eu/news/latest-news/global-operation-targets-noname05716-pro-russian-cybercrime-network/

## Folder Structure
Data is stored in two formats: raw output from control servers and as a structured TinyDB database.  Data is typically sorted by control server.   

part1
    - Timeframe: 8 Feb 2023 - 7 Dec 2023

part2:
    - Timeframe: 16 Nov 2023 - 3 Mar 2025

part3: 
    - Timeframe: 2 Jun 2025-  2 July 2025

In each part's folder is:

`/databases`
    - this contains single json file for each control server
    - db_{C2 IP Address (port 443 if there is not a :PORT)}
    - each json file used by python TinyDB
    - easy to parse with JQ

`/logs`
    - in logs, there is a folder for each C2 server (logs_{C2 IP Address})
    - This contins the raw JSON response from the control servers for each time the both fetched new targets.  


## Shoutz
This data was collected thanks to the work of a collaboration between researchers.     

Slava Ukraini :flag-ua: 
