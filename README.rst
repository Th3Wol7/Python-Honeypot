HoneyPot
======
HoneyPot is a python application that can be used to create a honeypot to detect intrusions. It works by setting up listeners on various ports and monitoring incoming traffic. If any suspicious activity is detected, an alert is sent to the system using the desktop notification.

Prerequisites
----

To run HoneyPot, you must have Python 3.x installed on your system. Additionally, you need to install the following python packages:

- `gi `
- `scapy `
- ` Notify `

You can install these packages using the following command:

`pip install gi scapy Notify`

Usage
----
To use HoneyPot, simply run the __init__.py file using the following command:

markdown

`python __init__.py`

Configuration
____
The following configurations can be made in the __init__.py file before running the application:

bind_ip
Set the IP address of the machine that you want the honeypot to run on.

ports
Provide a list of ports that the honeypot should listen on.

log_filepath
Set the filepath of the log file. The log file will store information about any connections made to the honeypot.

Limitations
-----
The application currently only supports monitoring traffic on ports 21, 22, 80 and 443. To monitor traffic on other ports, modify the filter_expr variable in the capture_packets method of the HoneyPot class.
The application does not support persistent storage of logs. Logs are overwritten every time the application is run.
