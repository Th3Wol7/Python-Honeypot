import gi
import threading
import logging
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw

gi.require_version('Notify', '0.7')
from gi.repository import Notify
from socket import socket, timeout
from scapy.all import sniff


class HoneyPot(object):
    def __init__(self, bind_ip, ports, log_filepath):
        self.failed_attempts = None
        if len(ports) < 1:  # Checking ports before configuring logger
            raise Exception("No ports were provided.")

        self.bind_ip = bind_ip
        self.log_filepath = log_filepath
        self.ports = ports
        self.listener_threads = {}  # Stores all running client threads
        self.logger = self.configure_logging()  # Setting up logging configuration

        self.logger.info("Initializing Honeypot...")
        self.logger.info("Ports: %s" % self.ports)
        self.logger.info("Log filepath: %s" % self.log_filepath)
        Notify.init("Desktop Notification")
        self.start_packet_capture()  # Start watching necessary ports once honeypot has started

    def handle_connection(self, connection, port, remote_port, ip):  # where connection is the client socket
        # making a log once a connection was made
        self.logger.info("New connection on port %s from %s:%d" % (port, ip, remote_port))
        connection.settimeout(10)  # Allowing socket to be open for 10 seconds before timeout
        try:
            data = connection.recv(65536)  # storing 65536 (maximum) bits of any data that was sent before socket
            # timeout

            # conducting second log if data was sent over port before timeout
            self.logger.info("Data received on port %s from %s:%d - %s " % (port, ip, remote_port, data))

            # Intrusion detection Implementations:
            # for possible SQL injection
            if "SELECT" in data.decode():
                self.logger.warning(
                    "Possible SQL injection attempt on port %s from %s:%d - %s" % (port, ip, remote_port, data))

            # For certain keywords
            if b'password' in data or b'login' in data or b'root' in data:
                # Sending alert to the system if certain keywords are detected in data sent through ports
                message = ("Intrusion detected on port %s from %s: %d.\nPossible credential hijack!" % (
                    port, ip, remote_port))
                alert = Notify.Notification.new("Intrusion ALERT!", message, "dialog-warning")
                alert.show()
                self.logger.warning("Intrusion detected on port %s from %s: %d.\nPossible credential hijack!" % (
                    port, ip, remote_port))
            connection.send("Access denied.\n".encode('utf8'))
        except timeout:
            pass
        connection.close()

    def start_new_listener_thread(self, port):
        # Creating a new listener for each port
        listener = socket()  # Defaults (socket.AF INET, socket.SOCK_STREAM)
        listener.bind((self.bind_ip, int(port)))
        listener.listen(5)  # NUmber of queued connections the listener can accept
        while True:
            client, addr = listener.accept()
            # whenever a client connects, start a new thread and handle the connection as specified in method
            client_handler = threading.Thread(target=self.handle_connection, args=(client, port, addr[1], addr[0]))
            client_handler.start()

    def start_monitoring(self):
        for port in self.ports:
            # Where the server is listening store new thread in dictionary then start it
            self.listener_threads[port] = threading.Thread(target=self.start_new_listener_thread, args=(port,))
            self.listener_threads[port].start()

    def configure_logging(self):
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s    %(levelname)-8s %(message)s',
                            datefmt='%d-%m-%Y %H:%M',
                            filename=self.log_filepath,
                            filemode='w')  # NTS: Revisit file mode later - may change to a to keep log after closing
        logger = logging.getLogger(__name__)  # Creating a logger for the name of the file
        # Creating a console handler so data logged to the log file is also displayed in the console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        logger.addHandler(console_handler)
        return logger

    def start_packet_capture(self):  # Continuous process that never ends until honeypot terminates
        # Define the filter expression
        filter_expr = "tcp and (port 21 or port 22 or port 80 or port 443)"  # or port 25 or port 53 or port 443 or
        # port 135 or port 8080)"
        # To allow the main thread to continue executing, the packet capture is created in its own separate thread to
        # allowing capturing to happen in the background since it is a never 'ending' and would cause main to be 'stuck'
        capture_thread = threading.Thread(target=self.capture_packets, args=(filter_expr,))
        capture_thread.start()

    def capture_packets(self, pkt):
        # Extracting relevant packet data
        while True:
            pkt = sniff(count=1)[0]
            pkt_data = None
            if IP in pkt and TCP in pkt:
                pkt_data = {
                    'source': pkt[IP].src,
                    'destination': pkt[IP].dst,
                    'time': pkt.time,
                    'src_port': pkt[TCP].sport,
                    'dst_port': pkt[TCP].dport,
                    'payload': str(pkt[TCP].payload)
                }
            # Conducting Intrusion detection implementations:
            if pkt.haslayer(Raw) and pkt[TCP].dport in [80, 8080]:
                # Extracting user agent from HTTP packet
                http_payload = pkt.getlayer(Raw).load
                if b"User-Agent" in http_payload:
                    user_agent = http_payload.split(b"User-Agent: ")[1].split(b"\r\n")[0].decode()
                    self.logger.info(f"User agent: {user_agent}")
                    # Check if packet is a SYN packet
                    if pkt[TCP].flags == 'S':
                        self.logger.info(
                            "SYN packet detected from %s:%s to %s:%s" % (
                                pkt_data['source'], pkt_data['src_port'], pkt_data['destination'],
                                pkt_data['dst_port']))

                    # Check if packet is a RST packet
                    if pkt[TCP].flags == 'R':
                        self.logger.warning(
                            "RST packet detected from %s:%s to %s:%s" % (
                                pkt_data['source'], pkt_data['src_port'], pkt_data['destination'],
                                pkt_data['dst_port']))

                    # Check if packet is a FIN packet
                    if pkt[TCP].flags == 'F':
                        self.logger.warning("FIN packet detected from %s:%s to %s:%s" % (
                            pkt_data['source'], pkt_data['src_port'], pkt_data['destination'],
                            pkt_data['dst_port']))

            # Detecting possible port scanning
            if pkt[TCP].flags == 2:
                self.logger.warning("Possible port scanning on port %s from %s" % (pkt[TCP].dport, pkt[IP].src))

            # Detecting possible DoS attack
            if len(pkt[TCP].payload) > 10000:
                self.logger.warning("Possible DoS attack on port %s from %s" % (pkt[TCP].dport, pkt[IP].src))

            # Logging the extracted data
            self.logger.info("Packet captured on port has %s" % pkt_data)

            # Conducting further analysis on packet data
            # Check for potential SQL injection
            if "SELECT" in pkt_data['payload']:
                self.logger.warning("Possible SQL injection attempt on port from %s:%d - %s\n" % (
                    pkt_data['source'], pkt_data['src_port'], pkt_data['payload']))

            # Check for potential XSS attack
            if "<script>" in pkt_data['payload']:
                self.logger.warning("Possible XSS attack on port from %s:%d - %s\n" % (
                    pkt_data['source'], pkt_data['src_port'], pkt_data['payload']))

            # Check for potential directory traversal attack
            if "../" in pkt_data['payload']:
                self.logger.warning("Possible directory traversal attack on port from %s:%d - %s\n" % (
                    pkt_data['source'], pkt_data['src_port'], pkt_data['payload']))

            # Check for potential file inclusion attack
            if "file=" in pkt_data['payload']:
                self.logger.warning("Possible file inclusion attack on port from %s:%d - %s" % (
                    pkt_data['source'], pkt_data['src_port'], pkt_data['payload']))

            # Check for potential command injection attack
            if ";" in pkt_data['payload']:
                self.logger.warning("Possible command injection attack on port from %s:%d - %s" % (
                    pkt_data['source'], pkt_data['src_port'], pkt_data['payload']))

            # Check for potential buffer overflow attack
            if len(pkt_data['payload']) > 1000:
                self.logger.warning("Possible buffer overflow attack on port from %s:%d - %s" % (
                    pkt_data['source'], pkt_data['src_port'], pkt_data['payload']))

            # Detecting possible DoS attack
            if len(pkt[TCP].payload) > 10000:
                self.logger.warning("Possible DoS attack on port %s from %s" % (pkt[TCP].dport, pkt[IP].src))

            # Detecting possible malware distribution
            if "GET" in pkt[TCP].payload.decode() and "malware" in pkt[TCP].payload.decode():
                self.logger.warning(
                    "Possible malware distribution on port %s from %s" % (pkt[TCP].dport, pkt[IP].src))

            """
            # Implementing rule to block IP addresses for repeated failed login attempts
            if "POST" in pkt[TCP].payload.decode() and "login" in pkt[TCP].payload.decode() and "password" in pkt[TCP].payload.decode():
                failed_attempts = self.get_failed_login_attempts(pkt[IP].src)
                if failed_attempts >= 3:
                    self.logger.warning(
                        "Blocking IP address %s due to repeated failed login attempts" % pkt[IP].src)
                    self.block_ip_address(pkt[IP].src)
                else:
                    self.increment_failed_login_attempts(pkt[IP].src)
            """

    # run method for starting a main thread on the server
    def run(self):
        self.start_monitoring()
