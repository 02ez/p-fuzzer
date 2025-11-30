#!/usr/bin/env python3
"""
NetworkServiceFuzzer - Modules 2 & 3: Fuzz Generator + Fault Detection
Lab environment only. Do not use outside of sandboxed testing.
Implements dynamic analysis (fuzzing) to detect crashes via payload escalation.
"""

import socket
import logging
import json
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
    handlers=[
        logging.FileHandler('fuzzer_detailed.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FuzzGenerator:
    """M2: Generates progressively larger fuzz payloads."""
    
    def __init__(self, pattern='A', initial_size=100, increment=200, max_size=10000):
        """
        Initialize fuzz generator.
        Args:
            pattern (str): Character to repeat (default 'A')
            initial_size (int): Starting payload size in bytes
            increment (int): Increase per iteration
            max_size (int): Maximum payload size before stopping
        """
        self.pattern = pattern
        self.current_size = initial_size
        self.increment = increment
        self.max_size = max_size
        self.payload_count = 0
    
    def next_payload(self):
        """
        Generate next fuzz payload.
        Returns:
            str: Next payload, or None if max_size exceeded
        """
        if self.current_size > self.max_size:
            return None
        
        payload = self.pattern * self.current_size
        self.payload_count += 1
        
        logger.debug(f"Generated payload #{self.payload_count}: {self.current_size} bytes")
        self.current_size += self.increment
        
        return payload
    
    def reset(self):
        """Reset generator to initial state."""
        self.current_size = self.initial_size
        self.payload_count = 0

class FaultDetector:
    """M3: Detects crashes and logs detailed fault information."""
    
    def __init__(self, target_ip, target_port, timeout=5):
        """
        Initialize fault detector.
        Args:
            target_ip (str): Target service IP address
            target_port (int): Target service port
            timeout (int): Socket timeout in seconds
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.crash_log = []
    
    def send_fuzz_payload(self, payload_data):
        """
        Send fuzz payload and detect fault.
        
        Returns:
            dict: {
                'success': bool (connection succeeded),
                'crashed': bool (service appears crashed),
                'payload_size': int,
                'error': str (user-facing message),
                'details': dict (detailed diagnostic info)
            }
        """
        result = {
            'success': False,
            'crashed': False,
            'payload_size': len(payload_data),
            'error': None,
            'details': {}
        }
        
        sock = None
        
        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            logger.debug(f"Attempting connection to {self.target_ip}:{self.target_port} "
                        f"with payload size {len(payload_data)} bytes")
            
            # Attempt connection
            sock.connect((self.target_ip, self.target_port))
            logger.debug(f"Successfully connected to {self.target_ip}:{self.target_port}")
            
            # Send the fuzzed payload
            sock.sendall(payload_data.encode('utf-8'))
            logger.debug(f"Payload sent ({len(payload_data)} bytes)")
            result['success'] = True
            
            # Attempt to receive response (detect immediate disconnects)
            try:
                response = sock.recv(1024)
                if response:
                    logger.debug(f"Received {len(response)} bytes from target")
            except socket.timeout:
                logger.debug(f"No response received within {self.timeout} seconds (timeout)")
        
        except socket.timeout:
            # Timeout on connect attempt
            result['crashed'] = True
            result['error'] = f"Connection timeout after {self.timeout}s (payload size: {len(payload_data)} bytes)"
            result['details'] = {
                'error_type': 'socket.timeout',
                'target': f"{self.target_ip}:{self.target_port}",
                'payload_size': len(payload_data),
                'timeout_threshold': self.timeout
            }
            logger.warning(f"POTENTIAL CRASH: Timeout connecting to {self.target_ip}:{self.target_port} "
                          f"at payload size {len(payload_data)}: {result['details']}")
            print(f"⚠ Service connection lost at payload size: {len(payload_data)} bytes")
        
        except socket.error as e:
            # Socket error (connection refused, reset, etc.) typically indicates crash
            result['crashed'] = True
            result['details'] = {
                'error_type': type(e).__name__,
                'error_message': str(e),
                'target': f"{self.target_ip}:{self.target_port}",
                'payload_size': len(payload_data),
                'timestamp': datetime.now().isoformat()
            }
            result['error'] = f"Service connection lost at payload size: {len(payload_data)} bytes"
            
            logger.error(f"CRASH DETECTED at {self.target_ip}:{self.target_port} "
                        f"(payload size: {len(payload_data)}). "
                        f"Exception: {type(e).__name__}: {str(e)}")
            print(f"⚠ {result['error']}")
        
        except Exception as e:
            # Catch any other unexpected exceptions
            result['crashed'] = True
            result['details'] = {
                'error_type': type(e).__name__,
                'error_message': str(e),
                'target': f"{self.target_ip}:{self.target_port}",
                'payload_size': len(payload_data),
                'timestamp': datetime.now().isoformat()
            }
            result['error'] = "Unexpected error during fuzzing attempt"
            
            logger.critical(f"UNEXPECTED ERROR at {self.target_ip}:{self.target_port} "
                           f"(payload size: {len(payload_data)}). "
                           f"Exception: {type(e).__name__}: {str(e)}")
            print(f"⚠ {result['error']} (see log for details)")
        
        finally:
            # Ensure socket is closed, even if an exception occurred
            if sock:
                try:
                    sock.close()
                    logger.debug("Socket closed gracefully")
                except Exception as e:
                    logger.warning(f"Error closing socket: {e}")
        
        return result
    
    def run_fuzz_campaign(self, fuzzer):
        """
        Run full fuzz campaign, logging crashes.
        
        Args:
            fuzzer (FuzzGenerator): Initialized fuzz generator instance
        
        Returns:
            list: List of crash records (payload_size, error details, timestamp)
        """
        logger.info(f"Starting fuzz campaign against {self.target_ip}:{self.target_port}")
        
        while True:
            payload = fuzzer.next_payload()
            if payload is None:
                logger.info("Maximum payload size reached. Fuzz campaign complete.")
                break
            
            payload_size = len(payload)
            result = self.send_fuzz_payload(payload)
            
            if result['crashed']:
                logger.error(f"CRASH LOGGED at payload size: {payload_size}")
                self.crash_log.append(result['details'])
            else:
                logger.info(f"Payload {fuzzer.payload_count}: {payload_size} bytes - OK")
        
        return self.crash_log
    
    def export_crash_log(self, filename='crash_log.json'):
        """Export crash log to JSON file."""
        with open(filename, 'w') as f:
            json.dump(self.crash_log, f, indent=2)
        logger.info(f"Crash log exported to {filename}")

def main():
    """Main function: run fuzz campaign."""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python m2_m3_fuzzer.py <target_ip> <target_port> [max_payload_size]")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    try:
        target_port = int(sys.argv[2])
    except ValueError:
        print("Error: target_port must be an integer")
        sys.exit(1)
    
    max_size = 5000
    if len(sys.argv) > 3:
        try:
            max_size = int(sys.argv[3])
        except ValueError:
            print("Error: max_payload_size must be an integer")
            sys.exit(1)
    
    logger.info("=" * 60)
    logger.info("NetworkServiceFuzzer - M2/M3 Campaign")
    logger.info("Lab environment only. Do not use outside of sandboxed testing.")
    logger.info("=" * 60)
    logger.info(f"Target: {target_ip}:{target_port}")
    logger.info(f"Max payload size: {max_size} bytes")
    
    # Initialize fuzzer and detector
    fuzzer = FuzzGenerator(pattern='A', initial_size=100, increment=200, max_size=max_size)
    detector = FaultDetector(target_ip, target_port, timeout=5)
    
    # Run fuzz campaign
    crashes = detector.run_fuzz_campaign(fuzzer)
    
    # Summary
    logger.info("=" * 60)
    logger.info(f"Fuzz campaign complete. Crashes detected: {len(crashes)}")
    
    if crashes:
        for i, crash in enumerate(crashes, 1):
            logger.info(f"Crash #{i}: Payload size {crash['payload_size']} bytes")
            logger.info(f"  Error: {crash['error_type']} - {crash.get('error_message', 'N/A')}")
            logger.info(f"  Timestamp: {crash['timestamp']}")
    
    # Export crash log
    detector.export_crash_log('crash_log.json')
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
