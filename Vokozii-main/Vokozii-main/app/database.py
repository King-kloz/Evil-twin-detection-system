"""
SQLite Database Module for Evil Twin Detection System
Implements concurrent-safe database operations with WAL mode
"""

import sqlite3
import os
from pathlib import Path
from datetime import datetime
from threading import Lock
from typing import List, Dict, Optional


class SecurityDatabase:
    def __init__(self, db_path: str = "security.db"):
        """
        Initialize SQLite database with Write-Ahead Logging (WAL) for concurrent safety.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.lock = Lock()
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create a database connection with WAL mode enabled."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initialize database tables if they don't exist."""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                # Create baselines table for storing known network configurations
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS baselines (
                        ssid TEXT NOT NULL,
                        bssid TEXT PRIMARY KEY,
                        akm TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create security_logs table for recording detected anomalies
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ssid TEXT NOT NULL,
                        bssid TEXT NOT NULL,
                        issue TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indices for faster queries
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_baselines_ssid ON baselines(ssid)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs(timestamp)
                """)
                
                conn.commit()
            except sqlite3.Error as e:
                print(f"Database initialization error: {e}")
            finally:
                conn.close()

    def save_baseline(self, networks: List[Dict[str, str]]) -> None:
        """
        Save discovered networks as security baselines.
        
        Args:
            networks: List of network dicts with keys: ssid, bssid, akm
        """
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                for network in networks:
                    cursor.execute("""
                        INSERT OR REPLACE INTO baselines (ssid, bssid, akm, timestamp)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """, (network.get("ssid", ""), network.get("bssid", ""), network.get("akm", "")))
                
                conn.commit()
            except sqlite3.Error as e:
                print(f"Error saving baseline: {e}")
                conn.rollback()
            finally:
                conn.close()

    def get_baselines(self) -> List[Dict[str, str]]:
        """
        Retrieve all stored network baselines.
        
        Returns:
            List of baseline network dictionaries
        """
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("SELECT ssid, bssid, akm FROM baselines")
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except sqlite3.Error as e:
                print(f"Error retrieving baselines: {e}")
                return []
            finally:
                conn.close()

    def log_incident(self, ssid: str, bssid: str, issue: str) -> None:
        """
        Log a security incident to the database.
        
        Args:
            ssid: Network SSID
            bssid: Network BSSID (MAC address)
            issue: Description of the security issue detected
        """
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    INSERT INTO security_logs (ssid, bssid, issue, timestamp)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (ssid, bssid, issue))
                
                conn.commit()
            except sqlite3.Error as e:
                print(f"Error logging incident: {e}")
                conn.rollback()
            finally:
                conn.close()

    def get_recent_incidents(self, limit: int = 100) -> List[Dict]:
        """
        Retrieve recent security incidents.
        
        Args:
            limit: Maximum number of incidents to retrieve
            
        Returns:
            List of incident records sorted by timestamp (newest first)
        """
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    SELECT id, ssid, bssid, issue, timestamp 
                    FROM security_logs 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except sqlite3.Error as e:
                print(f"Error retrieving incidents: {e}")
                return []
            finally:
                conn.close()

    def clear_old_logs(self, days: int = 30) -> None:
        """
        Clear security logs older than specified number of days.
        
        Args:
            days: Number of days to keep logs
        """
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    DELETE FROM security_logs 
                    WHERE timestamp < datetime('now', ? || ' days')
                """, (f"-{days}",))
                
                conn.commit()
            except sqlite3.Error as e:
                print(f"Error clearing old logs: {e}")
                conn.rollback()
            finally:
                conn.close()

    def get_baseline_by_ssid(self, ssid: str) -> List[Dict[str, str]]:
        """
        Get all baseline records for a specific SSID.
        
        Args:
            ssid: Network SSID to query
            
        Returns:
            List of baseline records matching the SSID
        """
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    SELECT ssid, bssid, akm FROM baselines WHERE ssid = ?
                """, (ssid,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except sqlite3.Error as e:
                print(f"Error retrieving baseline by SSID: {e}")
                return []
            finally:
                conn.close()
