"""
Detection Engine Module for Evil Twin Detection System
Implements WiFi scanning, baseline training, and security auditing
"""

import time
import threading
from typing import List, Dict, Callable, Optional
from datetime import datetime
import pywifi
from pywifi import const
from app.database import SecurityDatabase


class DetectionEngine:
    def __init__(self, db: SecurityDatabase, log_callback: Optional[Callable[[str], None]] = None):
        """
        Initialize the Detection Engine with pywifi scanning capabilities.
        
        Args:
            db: SecurityDatabase instance for persistence
            log_callback: Optional callback function for logging output
        """
        self.db = db
        self.log_callback = log_callback or self._default_log
        self.wifi = pywifi.PyWiFi()
        
        # Validate that we have at least one wireless interface
        try:
            self.iface = self.wifi.interfaces()[0]
            self._log(f"Initialized with interface: {self.iface.name()}")
        except IndexError:
            self._log("ERROR: No wireless interface detected on this system")
            self.iface = None

    def _default_log(self, message: str) -> None:
        """Default logging function prints to stdout."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def _log(self, message: str) -> None:
        """Log message through callback."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        self.log_callback(formatted_msg)

    def scan_nearby(self) -> bool:
        """
        Initiate a WiFi scan and wait for results to populate in OS cache.
        Must sleep 1.5+ seconds for proper OS cache population.
        
        Returns:
            True if scan completed successfully, False otherwise
        """
        if not self.iface:
            self._log("ERROR: No wireless interface available")
            return False
        
        try:
            self._log("Scanning for nearby networks...")
            self.iface.scan()
            # Wait for OS to populate the scan results cache
            time.sleep(1.5)
            self._log("Scan cache populated")
            return True
        except Exception as e:
            self._log(f"Scan error: {e}")
            return False

    def get_scan_results(self) -> List[Dict[str, str]]:
        """
        Retrieve WiFi scan results from the interface.
        Call scan_nearby() before this to ensure data is fresh.
        
        Returns:
            List of network dictionaries with keys: ssid, bssid, akm, signal
        """
        if not self.iface:
            return []
        
        try:
            scan_results = self.iface.scan_results()
            networks = []
            
            for network in scan_results:
                # Extract authentication key management (security type)
                akm_list = network.akm or ["UNKNOWN"]
                akm = ", ".join([str(a) for a in akm_list[:2]])
                
                network_dict = {
                    "ssid": network.ssid or "[HIDDEN]",
                    "bssid": network.bssid or "UNKNOWN",
                    "akm": akm,
                    "signal": str(network.signal)
                }
                networks.append(network_dict)
            
            return networks
        except Exception as e:
            self._log(f"Error retrieving scan results: {e}")
            return []

    def perform_training(self, scan_count: int = 1) -> List[Dict[str, str]]:
        """
        Perform training by collecting nearby network scans.
        Returns a list of discovered networks to be saved as baselines.
        
        Args:
            scan_count: Number of scans to perform (more scans = more reliability)
            
        Returns:
            List of network dictionaries (ssid, bssid, akm)
        """
        self._log(f"Starting training scan (count: {scan_count})...")
        all_networks = {}
        
        for i in range(scan_count):
            self._log(f"Training scan {i + 1}/{scan_count}")
            
            if not self.scan_nearby():
                continue
            
            networks = self.get_scan_results()
            
            # Aggregate networks across multiple scans to get the most reliable data
            for network in networks:
                bssid = network["bssid"]
                if bssid not in all_networks:
                    all_networks[bssid] = network
            
            if i < scan_count - 1:
                time.sleep(0.5)  # Brief pause between scans
        
        result = list(all_networks.values())
        self._log(f"Training complete: Discovered {len(result)} unique networks")
        return result

    def audit_environment(self, alert_callback: Optional[Callable[[str, str, str], None]] = None) -> List[Dict]:
        """
        Audit the current wireless environment against known baselines.
        Detects unauthorized BSSIDs and security downgrades.
        
        Args:
            alert_callback: Optional callback(ssid, bssid, issue) for alerts
            
        Returns:
            List of detected anomalies
        """
        if not self.scan_nearby():
            self._log("ERROR: Could not perform audit scan")
            return []
        
        # Load baselines from database
        baselines = self.db.get_baselines()
        baseline_map = {b["bssid"]: b for b in baselines}
        baseline_ssids = {b["ssid"] for b in baselines}
        
        # Get current scan results
        current_networks = self.get_scan_results()
        anomalies = []
        
        self._log(f"Auditing {len(current_networks)} networks against {len(baselines)} baselines")
        
        for network in current_networks:
            ssid = network["ssid"]
            bssid = network["bssid"]
            current_akm = network["akm"]
            
            # Check 1: Unauthorized BSSID for known SSID
            if ssid in baseline_ssids and bssid not in baseline_map:
                # This SSID is known but BSSID is not - potential evil twin
                matching_baselines = self.db.get_baseline_by_ssid(ssid)
                if matching_baselines:
                    issue = f"Unauthorized BSSID detected for known SSID '{ssid}'. Expected: {[b['bssid'] for b in matching_baselines]}, Found: {bssid}"
                    anomalies.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "issue": issue,
                        "severity": "HIGH"
                    })
                    self._log(f"⚠ ALERT: {issue}")
                    self.db.log_incident(ssid, bssid, issue)
                    if alert_callback:
                        alert_callback(ssid, bssid, "UNAUTHORIZED_BSSID")
            
            # Check 2: Security downgrade
            elif bssid in baseline_map:
                baseline = baseline_map[bssid]
                baseline_akm = baseline["akm"]
                
                # Simple security downgrade check: if baseline has strong encryption
                # and current doesn't, flag it
                if self._is_security_downgrade(baseline_akm, current_akm):
                    issue = f"Security downgrade detected on '{ssid}' ({bssid}). Baseline: {baseline_akm}, Current: {current_akm}"
                    anomalies.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "issue": issue,
                        "severity": "MEDIUM"
                    })
                    self._log(f"⚠ WARNING: {issue}")
                    self.db.log_incident(ssid, bssid, issue)
                    if alert_callback:
                        alert_callback(ssid, bssid, "SECURITY_DOWNGRADE")
        
        # Check 3: Missing baseline networks (disappeared)
        current_bssids = {n["bssid"] for n in current_networks}
        for baseline in baselines:
            if baseline["bssid"] not in current_bssids:
                self._log(f"ℹ Info: Baseline network '{baseline['ssid']}' ({baseline['bssid']}) not currently visible")
        
        return anomalies

    def _is_security_downgrade(self, baseline_akm: str, current_akm: str) -> bool:
        """
        Determine if current AKM represents a security downgrade from baseline.
        
        Args:
            baseline_akm: Baseline authentication key management
            current_akm: Current authentication key management
            
        Returns:
            True if security has been downgraded
        """
        # Security hierarchy: WPA3 > WPA2 > WPA > OPEN
        security_levels = {
            "UNKNOWN": 0,
            "OPEN": 1,
            "WPA": 2,
            "WPA2": 3,
            "WPA3": 4
        }
        
        def get_max_level(akm_str: str) -> int:
            level = 0
            for keyword in security_levels:
                if keyword in akm_str.upper():
                    level = max(level, security_levels[keyword])
            return level
        
        baseline_level = get_max_level(baseline_akm)
        current_level = get_max_level(current_akm)
        
        # Downgrade if current level is less than baseline
        return current_level < baseline_level and baseline_level > 1

    def continuous_monitor(self, interval_seconds: int = 8, 
                          stop_event: Optional[threading.Event] = None,
                          alert_callback: Optional[Callable[[str, str, str], None]] = None) -> None:
        """
        Run continuous monitoring loop that audits environment periodically.
        
        Args:
            interval_seconds: Seconds between audits
            stop_event: threading.Event to signal monitoring stop
            alert_callback: Callback for alerts
        """
        self._log("Continuous monitoring started")
        
        while not (stop_event and stop_event.is_set()):
            try:
                anomalies = self.audit_environment(alert_callback)
                if not anomalies:
                    self._log("✓ Environment audit: No anomalies detected")
                else:
                    self._log(f"✗ Found {len(anomalies)} anomalies during audit")
                
                # Sleep with periodic checks for stop signal
                for _ in range(interval_seconds * 10):
                    if stop_event and stop_event.is_set():
                        break
                    time.sleep(0.1)
                    
            except Exception as e:
                self._log(f"Monitor error: {e}")
                time.sleep(interval_seconds)
        
        self._log("Continuous monitoring stopped")
