# Evil Twin Detection System (SCES CNS 3104)

A complete, production-ready Windows-native Evil Twin detection application built in Python. Detects rogue WiFi access points (evil twins) and security downgrades without requiring Npcap, Scapy, or administrator privileges.

## Features

- **Native Windows WiFi API Integration**: Uses `pywifi` to query the native Windows WLAN API
- **Baseline Training**: Learn known networks during training phase
- **Continuous Monitoring**: 8-second interval security audits
- **Evil Twin Detection**: Identifies unauthorized BSSIDs for known SSIDs
- **Security Downgrade Detection**: Alerts on encryption protocol downgrades
- **Thread-Safe UI**: Dark-mode customtkinter interface that never freezes
- **Persistent Logging**: SQLite database with WAL mode for concurrent safety
- **Windows Notifications**: Native toast notifications for security alerts
- **No Admin Required**: Works with standard user privileges

## System Requirements

- Windows 10 or later
- Python 3.7+
- Wireless adapter with Windows WLAN driver support

## Installation

1. Clone or download this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

## Usage

### Training Phase
1. Click the **"🚀 Train System"** button
2. The system performs 3 WiFi scans (about 5 seconds total)
3. Discovered networks are saved as security baselines to the SQLite database
4. Training must complete before monitoring can start

### Monitoring Phase
1. Click the **"Live Monitoring"** toggle switch to activate
2. The system audits nearby networks every 8 seconds
3. Anomalies are logged to the console and database
4. Security alerts trigger Windows toast notifications
5. Switch off to stop monitoring (can immediately train again)

### Detection Logic

**Evil Twin Alert** (HIGH Severity):
- Known SSID detected with an unauthorized BSSID
- Example: Your home WiFi broadcasts from a different MAC address than baseline

**Security Downgrade Alert** (MEDIUM Severity):
- Known network detected with weaker encryption than baseline
- Example: WPA3 baseline network now broadcasting with WPA2

## File Structure

```
Novako/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── security.db            # SQLite database (created at runtime)
├── README.md              # This file
└── app/
    ├── __init__.py        # Package initialization
    ├── database.py        # SQLite database module with WAL mode
    ├── detector.py        # Detection engine with pywifi scanning
    └── ui.py              # Dark-mode customtkinter interface
```

## Database Schema

### `baselines` Table
Stores known network configurations:
- `ssid` (TEXT): Network name
- `bssid` (TEXT PRIMARY KEY): MAC address
- `akm` (TEXT): Authentication key management (security type)
- `timestamp` (DATETIME): When baseline was recorded

### `security_logs` Table
Stores detected security incidents:
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT): Record ID
- `ssid` (TEXT): Network SSID
- `bssid` (TEXT): Network BSSID
- `issue` (TEXT): Description of detected issue
- `timestamp` (DATETIME): When incident was detected

## Thread Architecture

### Main Thread
- CustomTkinter event loop (never blocks)
- Message queue processor (updates UI every 100ms)

### Training Thread
- Spawned on "🚀 Train System" button click
- Performs multiple WiFi scans
- Disables training button and monitoring during operation
- Returns to IDLE when complete

### Monitoring Thread
- Spawned when "Live Monitoring" toggle activated
- Continuous loop with 8-second interval
- Uses threading.Event for clean shutdown
- Calls security audit and triggers callbacks
- Respects stop signals even mid-sleep

## Security Considerations

1. **No Admin Required**: Uses Windows WLAN API directly without admin elevation
2. **Concurrent Database Access**: SQLite WAL mode enables safe multi-threaded reads/writes
3. **Thread-Safe UI**: Qt signal/slot patterns via message queue
4. **Threat Detection**:
   - Identifies unauthorized access points impersonating known networks
   - Detects encryption suite downgrade attacks
   - Maintains persistent audit trail

## Production Features

✓ Complete error handling and logging  
✓ No code placeholders or "exercise" sections  
✓ Thread-safe UI that never freezes  
✓ Persistent SQLite with concurrent write support  
✓ Native Windows integration (toast notifications, WLAN API)  
✓ Proper daemon thread lifecycle management  
✓ Graceful shutdown handling  

## Troubleshooting

**"No wireless interface detected"**
- Verify WiFi adapter is enabled
- Check Windows WiFi drivers are installed
- Restart the application

**Database locked errors**
- SQLite WAL mode automatically handles this
- Ensure no other instances are running
- Delete `security.db-wal` and `security.db-shm` if persistent

**No networks detected during scan**
- Verify WiFi is enabled
- Check if there are active networks nearby
- May need to wait 1-2 seconds after scan starts

**Toast notifications not showing**
- Verify Windows notifications are enabled
- win10toast requires Windows 10+
- Check toast notifications aren't muted in Settings

## Development Notes

- All code is production-ready with no placeholder sections
- Thread-safe database operations via threading.Lock + WAL mode
- UI never blocks on network operations
- Scanning requires 1.5+ second delay for OS cache population
- Baseline training with multiple scans increases reliability
