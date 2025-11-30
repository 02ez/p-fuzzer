#!/usr/bin/env python3
"""
NetworkServiceFuzzer - Module 1: Connection Handler
Lab environment only. Do not use outside of sandboxed testing.
"""

import socket
import sys
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fuzzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ConnectionHandler:
    def __init__(self, target_ip, target_port, timeout=5):
        """
        Initialize connection handler.
        Args:
            target_ip (str): Target service IP address
            target_port (int): Target service port
            timeout (int): Socket timeout in seconds
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.socket = None
        
    def connect(self):
        """
        Establish TCP connection to target.
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            logger.info(f"Attempting connection to {self.target_ip}:{self.target_port}")
            self.socket.connect((self.target_ip, self.target_port))
            logger.info(f"Successfully connected to {self.target_ip}:{self.target_port}")
            return True
        except socket.timeout:
            logger.error(f"Connection timeout after {self.timeout} seconds")
            return False
        except socket.error as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def send_probe(self, probe_data):
        """
        Send probe command to target.
        Args:
            probe_data (str): Data to send
        Returns:
            str: Response data if received, None otherwise
        """
        if not self.socket:
            logger.error("Not connected. Call connect() first.")
            return None
        
        try:
            self.socket.send(probe_data.encode())
            logger.debug(f"Sent probe: {probe_data}")
            
            # Attempt to receive response
            response = self.socket.recv(1024).decode()
            logger.debug(f"Received response: {response[:100]}...")
            return response
        except socket.timeout:
            logger.warning("Receive timeout - no response from target")
            return None
        except socket.error as e:
            logger.error(f"Send/receive error: {e}")
            return None
    
    def disconnect(self):
        """Close the socket connection."""
        if self.socket:
            self.socket.close()
            logger.info("Connection closed")
    
    def __del__(self):
        """Ensure socket is closed on object destruction."""
        self.disconnect()

def main():
    """Main function: test connection handler."""
    if len(sys.argv) < 3:
        print("Usage: python m1_connection_handler.py <target_ip> <target_port>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    try:
        target_port = int(sys.argv[2])
    except ValueError:
        print("Error: target_port must be an integer")
        sys.exit(1)
    
    logger.info(f"Starting M1 Connection Handler - Lab Environment Only")
    logger.info(f"Target: {target_ip}:{target_port}")
    
    handler = ConnectionHandler(target_ip, target_port, timeout=5)
    
    if handler.connect():
        # Send a simple probe (e.g., HTTP GET or empty CRLF)
        response = handler.send_probe("HELO\r\n")
        if response:
            logger.info(f"Probe successful. Response length: {len(response)}")
        else:
            logger.warning("Probe sent but no response received")
    else:
        logger.error("Failed to establish connection")
    
    handler.disconnect()
    logger.info("M1 test complete")

if __name__ == "__main__":
    main()
