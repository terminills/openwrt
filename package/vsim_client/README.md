# OpenWrt vSIM Client

This package provides a vSIM client for OpenWrt that interacts with a Flask CRM API for virtual SIM card management.

## Features

- **Periodic Heartbeats**: Sends heartbeat with system diagnostics every 60 seconds (configurable)
- **Command Polling**: Polls for pending commands every 30 seconds (configurable) 
- **Command Execution**: Executes received commands and acknowledges completion
- **Error Reporting**: Reports errors to the CRM system
- **Flexible Configuration**: Supports UCI config, environment variables, and command line arguments
- **Comprehensive Logging**: Logs to /var/log/vsim_client.log with configurable levels
- **OpenWrt Integration**: Includes init script and UCI configuration

## Installation

The package can be built as part of the OpenWrt build system:

```bash
make package/vsim_client/compile
```

Or installed manually by copying the files:

```bash
# Copy script
cp files/usr/bin/openwrt_vsim_client.py /usr/bin/
chmod +x /usr/bin/openwrt_vsim_client.py

# Copy configuration
cp files/etc/config/vsim_client /etc/config/

# Copy and enable init script  
cp files/etc/init.d/vsim_client /etc/init.d/
chmod +x /etc/init.d/vsim_client
/etc/init.d/vsim_client enable
```

## Configuration

### UCI Configuration (/etc/config/vsim_client)

```
config vsim_client 'main'
    option api_url 'http://your-crm-server.com/api'
    option api_key 'your-api-key'
    option device_id 'unique-device-id'
    option heartbeat_interval '60'
    option command_poll_interval '30'
    option log_level 'INFO'
```

### Environment Variables

- `CRM_API_URL` - CRM API base URL
- `CRM_API_KEY` - API authentication key  
- `VSIM_DEVICE_ID` - Device identifier
- `HEARTBEAT_INTERVAL` - Heartbeat interval in seconds
- `COMMAND_POLL_INTERVAL` - Command polling interval in seconds
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)
- `LOG_FILE` - Log file path

### Command Line Arguments

```bash
openwrt_vsim_client.py --help
openwrt_vsim_client.py --api-url http://crm.example.com/api --device-id router01
openwrt_vsim_client.py --test-connection
openwrt_vsim_client.py --oneshot  # Run one cycle and exit
```

## Usage

### Service Management

```bash
# Start the service
/etc/init.d/vsim_client start

# Stop the service
/etc/init.d/vsim_client stop

# Check status
/etc/init.d/vsim_client status

# View logs
tail -f /var/log/vsim_client.log
```

### Manual Execution

```bash
# Run in foreground with debug logging
openwrt_vsim_client.py --log-level DEBUG

# Test connection to CRM
openwrt_vsim_client.py --test-connection

# Run one heartbeat/command cycle
openwrt_vsim_client.py --oneshot
```

## API Endpoints

The client interacts with the following CRM API endpoints:

- `POST /api/vsim/heartbeat` - Send heartbeat with diagnostics
- `GET /api/vsim/commands/{device_id}` - Poll for pending commands
- `POST /api/vsim/commands/ack` - Acknowledge command execution
- `POST /api/vsim/errors` - Report errors

## Dependencies

- python3
- python3-requests

## Diagnostics Data

The heartbeat includes the following system diagnostics:

- System uptime
- Memory usage (total, free, available)
- Load average
- Network interface information
- Storage usage
- Device timestamp

## Error Handling

- Automatic retry with exponential backoff for API failures
- Graceful handling of network connectivity issues
- Fallback logging locations if /var/log is not writable
- Command execution timeouts (5 minutes)

## Security

- API key authentication support
- Command output size limits (4KB)
- Input validation for configuration parameters

## Compatibility

- OpenWrt 23.05+
- Python 3.6+
- Works with procd process management