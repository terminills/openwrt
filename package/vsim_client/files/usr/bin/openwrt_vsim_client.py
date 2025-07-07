#!/usr/bin/env python3
"""
OpenWrt vSIM Client Script

This script interacts with Flask CRM API endpoints for vSIM management,
including assignment, heartbeats, error reporting, command polling, and acknowledgment.

Compatible with OpenWrt 23.05+
Dependencies: python3, python3-requests

Configuration sources (in order of precedence):
1. Environment variables
2. /etc/config/vsim_client

Copyright (C) 2025 OpenWrt.org
Licensed under GPL-2.0+
"""

import sys
import os
import time
import json
import logging
import threading
import subprocess
import socket
import re
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import requests
except ImportError:
    print("Error: python3-requests package is required but not installed", file=sys.stderr)
    sys.exit(1)


class VSIMClient:
    """OpenWrt vSIM Client for CRM API interaction"""
    
    def __init__(self):
        self.config = self.load_config()
        self.setup_logging()
        self.session = requests.Session()
        self.session.timeout = self.config.get('api_timeout', 30)
        self.device_id = self.get_device_id()
        self.running = True
        
        # Set up request headers
        self.session.headers.update({
            'User-Agent': f'OpenWrt-vSIM-Client/1.0 ({self.device_id})',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        if self.config.get('api_key'):
            self.session.headers['Authorization'] = f"Bearer {self.config['api_key']}"
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables and config file"""
        config = {}
        
        # Default configuration
        defaults = {
            'crm_api_url': 'http://localhost:5000/api',
            'heartbeat_interval': 60,
            'command_poll_interval': 30,
            'api_timeout': 30,
            'log_level': 'INFO',
            'log_file': '/var/log/vsim_client.log',
            'max_retries': 3,
            'retry_delay': 5
        }
        
        # Load from environment variables
        env_mapping = {
            'CRM_API_URL': 'crm_api_url',
            'CRM_API_KEY': 'api_key',
            'VSIM_DEVICE_ID': 'device_id',
            'HEARTBEAT_INTERVAL': 'heartbeat_interval',
            'COMMAND_POLL_INTERVAL': 'command_poll_interval',
            'API_TIMEOUT': 'api_timeout',
            'LOG_LEVEL': 'log_level',
            'LOG_FILE': 'log_file',
            'MAX_RETRIES': 'max_retries',
            'RETRY_DELAY': 'retry_delay'
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                # Convert numeric values
                if config_key in ['heartbeat_interval', 'command_poll_interval', 'api_timeout', 'max_retries', 'retry_delay']:
                    try:
                        config[config_key] = int(value)
                    except ValueError:
                        config[config_key] = defaults.get(config_key, 30)
                else:
                    config[config_key] = value
        
        # Load from UCI config file
        uci_config = self.load_uci_config()
        for key, value in uci_config.items():
            if key not in config:  # Environment variables take precedence
                config[key] = value
        
        # Apply defaults for missing values
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
        
        return config
    
    def load_uci_config(self) -> Dict[str, Any]:
        """Load configuration from UCI config file"""
        config = {}
        config_file = '/etc/config/vsim_client'
        
        if not os.path.exists(config_file):
            return config
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Parse UCI config format
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('option '):
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        key = parts[1]
                        value = parts[2].strip("'\"")
                        
                        # Map UCI keys to internal config keys
                        key_mapping = {
                            'api_url': 'crm_api_url',
                            'api_key': 'api_key',
                            'device_id': 'device_id',
                            'heartbeat_interval': 'heartbeat_interval',
                            'command_poll_interval': 'command_poll_interval',
                            'api_timeout': 'api_timeout',
                            'log_level': 'log_level',
                            'log_file': 'log_file',
                            'max_retries': 'max_retries',
                            'retry_delay': 'retry_delay'
                        }
                        
                        mapped_key = key_mapping.get(key, key)
                        
                        # Convert numeric values
                        if mapped_key in ['heartbeat_interval', 'command_poll_interval', 'api_timeout', 'max_retries', 'retry_delay']:
                            try:
                                config[mapped_key] = int(value)
                            except ValueError:
                                pass
                        else:
                            config[mapped_key] = value
        
        except Exception as e:
            print(f"Warning: Failed to load UCI config: {e}", file=sys.stderr)
        
        return config
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config['log_level'].upper(), logging.INFO)
        log_file = self.config['log_file']
        
        # Ensure log directory exists and is writable
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError:
                log_file = '/tmp/vsim_client.log'
        
        # Test if log file is writable
        try:
            with open(log_file, 'a'):
                pass
        except (OSError, PermissionError):
            log_file = '/tmp/vsim_client.log'
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger('vsim_client')
        self.logger.info(f"vSIM Client starting with config: {self.config}")
        if log_file != self.config['log_file']:
            self.logger.warning(f"Log file changed to {log_file} due to permission issues")
    
    def get_device_id(self) -> str:
        """Get unique device identifier"""
        if self.config.get('device_id'):
            return self.config['device_id']
        
        # Try to get from UCI system config
        try:
            result = subprocess.run(['uci', 'get', 'system.@system[0].hostname'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname:
                    return hostname
        except Exception:
            pass
        
        # Fallback to MAC address
        try:
            result = subprocess.run(['cat', '/sys/class/net/eth0/address'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                mac = result.stdout.strip().replace(':', '')
                return f"openwrt-{mac}"
        except Exception:
            pass
        
        # Final fallback
        return f"openwrt-{socket.gethostname()}-{int(time.time())}"
    
    def get_diagnostics(self) -> Dict[str, Any]:
        """Collect system diagnostics information"""
        diagnostics = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'device_id': self.device_id,
            'uptime': self.get_uptime(),
            'memory': self.get_memory_info(),
            'load': self.get_load_average(),
            'network': self.get_network_info(),
            'storage': self.get_storage_info()
        }
        
        return diagnostics
    
    def get_uptime(self) -> Optional[float]:
        """Get system uptime in seconds"""
        try:
            with open('/proc/uptime', 'r') as f:
                return float(f.read().split()[0])
        except Exception:
            return None
    
    def get_memory_info(self) -> Dict[str, int]:
        """Get memory information"""
        memory = {}
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith(('MemTotal:', 'MemFree:', 'MemAvailable:')):
                        key, value = line.split(':')
                        memory[key.lower()] = int(value.split()[0]) * 1024  # Convert KB to bytes
        except Exception:
            pass
        return memory
    
    def get_load_average(self) -> Optional[str]:
        """Get system load average"""
        try:
            with open('/proc/loadavg', 'r') as f:
                return f.read().strip()
        except Exception:
            return None
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get network interface information"""
        network = {}
        try:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                network['interfaces'] = self.parse_ip_addr(result.stdout)
        except Exception:
            pass
        return network
    
    def parse_ip_addr(self, output: str) -> Dict[str, Dict[str, Any]]:
        """Parse ip addr show output"""
        interfaces = {}
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            if re.match(r'^\d+:', line):
                parts = line.split()
                if len(parts) >= 2:
                    current_interface = parts[1].rstrip(':')
                    interfaces[current_interface] = {'addresses': []}
            elif line.startswith('inet ') and current_interface:
                parts = line.split()
                if len(parts) >= 2:
                    interfaces[current_interface]['addresses'].append(parts[1])
        
        return interfaces
    
    def get_storage_info(self) -> Dict[str, Any]:
        """Get storage information"""
        storage = {}
        try:
            result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                storage['disk_usage'] = result.stdout
        except Exception:
            pass
        return storage
    
    def api_request(self, method: str, endpoint: str, data: Optional[Dict] = None, retries: int = None) -> Optional[Dict]:
        """Make API request with retry logic"""
        if retries is None:
            retries = self.config['max_retries']
        
        url = f"{self.config['crm_api_url']}/{endpoint.lstrip('/')}"
        
        for attempt in range(retries + 1):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, params=data)
                elif method.upper() == 'POST':
                    response = self.session.post(url, json=data)
                elif method.upper() == 'PUT':
                    response = self.session.put(url, json=data)
                else:
                    self.logger.error(f"Unsupported HTTP method: {method}")
                    return None
                
                response.raise_for_status()
                
                if response.content:
                    return response.json()
                else:
                    return {}
                
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"API request failed (attempt {attempt + 1}/{retries + 1}): {e}")
                if attempt < retries:
                    time.sleep(self.config['retry_delay'])
                else:
                    self.logger.error(f"API request failed after {retries + 1} attempts")
                    return None
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to decode API response: {e}")
                return None
    
    def send_heartbeat(self):
        """Send heartbeat with diagnostics to CRM"""
        self.logger.debug("Sending heartbeat")
        
        diagnostics = self.get_diagnostics()
        heartbeat_data = {
            'device_id': self.device_id,
            'timestamp': diagnostics['timestamp'],
            'status': 'active',
            'diagnostics': diagnostics
        }
        
        response = self.api_request('POST', '/vsim/heartbeat', heartbeat_data)
        if response:
            self.logger.info("Heartbeat sent successfully")
        else:
            self.logger.error("Failed to send heartbeat")
    
    def poll_commands(self):
        """Poll for pending commands from CRM"""
        self.logger.debug("Polling for commands")
        
        response = self.api_request('GET', f'/vsim/commands/{self.device_id}')
        if response and response.get('commands'):
            for command in response['commands']:
                self.execute_command(command)
    
    def execute_command(self, command: Dict[str, Any]):
        """Execute a command and acknowledge it"""
        command_id = command.get('id')
        command_text = command.get('command', '')
        
        self.logger.info(f"Executing command {command_id}: {command_text}")
        
        try:
            # Execute command with timeout
            result = subprocess.run(
                command_text,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            self.acknowledge_command(command_id, success, output)
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command {command_id} timed out")
            self.acknowledge_command(command_id, False, "Command execution timed out")
        except Exception as e:
            self.logger.error(f"Failed to execute command {command_id}: {e}")
            self.acknowledge_command(command_id, False, str(e))
    
    def acknowledge_command(self, command_id: str, success: bool, output: str):
        """Acknowledge command execution result"""
        ack_data = {
            'command_id': command_id,
            'device_id': self.device_id,
            'success': success,
            'output': output[:4096],  # Limit output size
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        response = self.api_request('POST', '/vsim/commands/ack', ack_data)
        if response:
            self.logger.info(f"Command {command_id} acknowledged successfully")
        else:
            self.logger.error(f"Failed to acknowledge command {command_id}")
    
    def report_error(self, error_type: str, message: str, details: Optional[Dict] = None):
        """Report error to CRM"""
        error_data = {
            'device_id': self.device_id,
            'error_type': error_type,
            'message': message,
            'details': details or {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        response = self.api_request('POST', '/vsim/errors', error_data)
        if response:
            self.logger.info(f"Error reported successfully: {error_type}")
        else:
            self.logger.error(f"Failed to report error: {error_type}")
    
    def heartbeat_loop(self):
        """Main heartbeat loop"""
        while self.running:
            try:
                self.send_heartbeat()
            except Exception as e:
                self.logger.error(f"Heartbeat loop error: {e}")
                self.report_error('heartbeat_error', str(e))
            
            time.sleep(self.config['heartbeat_interval'])
    
    def command_poll_loop(self):
        """Main command polling loop"""
        while self.running:
            try:
                self.poll_commands()
            except Exception as e:
                self.logger.error(f"Command poll loop error: {e}")
                self.report_error('command_poll_error', str(e))
            
            time.sleep(self.config['command_poll_interval'])
    
    def run(self):
        """Run the vSIM client"""
        self.logger.info(f"Starting vSIM client for device: {self.device_id}")
        
        # Start background threads
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        command_thread = threading.Thread(target=self.command_poll_loop, daemon=True)
        
        heartbeat_thread.start()
        command_thread.start()
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal, shutting down...")
            self.running = False
        except Exception as e:
            self.logger.error(f"Unexpected error in main loop: {e}")
            self.report_error('main_loop_error', str(e))
        
        # Wait for threads to finish
        heartbeat_thread.join(timeout=5)
        command_thread.join(timeout=5)
        
        self.logger.info("vSIM client stopped")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='OpenWrt vSIM Client - Interacts with Flask CRM API for vSIM management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration sources (in order of precedence):
1. Command line arguments
2. Environment variables 
3. /etc/config/vsim_client UCI configuration

Environment variables:
  CRM_API_URL           - CRM API base URL
  CRM_API_KEY           - API authentication key
  VSIM_DEVICE_ID        - Device identifier
  HEARTBEAT_INTERVAL    - Heartbeat interval in seconds
  COMMAND_POLL_INTERVAL - Command polling interval in seconds
  LOG_LEVEL             - Logging level (DEBUG, INFO, WARNING, ERROR)
  LOG_FILE              - Log file path

Examples:
  openwrt_vsim_client.py
  openwrt_vsim_client.py --api-url http://crm.example.com/api --device-id router01
  openwrt_vsim_client.py --test-connection
        """
    )
    
    parser.add_argument('--version', action='version', version='OpenWrt vSIM Client 1.0.0')
    parser.add_argument('--api-url', help='CRM API base URL')
    parser.add_argument('--api-key', help='API authentication key')
    parser.add_argument('--device-id', help='Device identifier')
    parser.add_argument('--heartbeat-interval', type=int, help='Heartbeat interval in seconds')
    parser.add_argument('--command-poll-interval', type=int, help='Command polling interval in seconds')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Logging level')
    parser.add_argument('--log-file', help='Log file path')
    parser.add_argument('--test-connection', action='store_true', help='Test API connection and exit')
    parser.add_argument('--oneshot', action='store_true', help='Run one heartbeat/command poll cycle and exit')
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Apply command line arguments to environment
    if args.api_url:
        os.environ['CRM_API_URL'] = args.api_url
    if args.api_key:
        os.environ['CRM_API_KEY'] = args.api_key
    if args.device_id:
        os.environ['VSIM_DEVICE_ID'] = args.device_id
    if args.heartbeat_interval:
        os.environ['HEARTBEAT_INTERVAL'] = str(args.heartbeat_interval)
    if args.command_poll_interval:
        os.environ['COMMAND_POLL_INTERVAL'] = str(args.command_poll_interval)
    if args.log_level:
        os.environ['LOG_LEVEL'] = args.log_level
    if args.log_file:
        os.environ['LOG_FILE'] = args.log_file
    
    client = VSIMClient()
    
    if args.test_connection:
        # Test connection and exit
        print(f"Testing connection to {client.config['crm_api_url']}...")
        response = client.api_request('GET', '/health')
        if response:
            print("✓ Connection successful")
            sys.exit(0)
        else:
            print("✗ Connection failed")
            sys.exit(1)
    
    if args.oneshot:
        # Run one cycle and exit
        print("Running one-shot mode...")
        client.send_heartbeat()
        client.poll_commands()
        print("One-shot mode completed")
        sys.exit(0)
    
    # Normal daemon mode
    client.run()


if __name__ == '__main__':
    main()