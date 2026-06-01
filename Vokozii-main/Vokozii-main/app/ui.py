"""
User Interface Module for Evil Twin Detection System
Implements dark-mode UI with customtkinter and thread-safe monitoring
"""

import tkinter as tk
from tkinter import scrolledtext
import customtkinter as ctk
import threading
import queue
from typing import Callable, Optional
from datetime import datetime
from app.database import SecurityDatabase
from app.detector import DetectionEngine

try:
    from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False


class SecurityApp(ctk.CTk):
    def __init__(self, db: SecurityDatabase):
        """
        Initialize the Security UI application with dark mode.
        
        Args:
            db: SecurityDatabase instance
        """
        super().__init__()
        
        self.db = db
        self.detector: Optional[DetectionEngine] = None
        self.message_queue: queue.Queue = queue.Queue()
        
        # Threading control
        self.monitoring_active = False
        self.training_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.monitor_stop_event: Optional[threading.Event] = None
        self.ui_thread: Optional[threading.Thread] = None
        
        # Toast notifier setup
        self.toaster = ToastNotifier() if TOAST_AVAILABLE else None
        
        # Configure window
        self.title("Evil Twin Detection System (SCES CNS 3104)")
        self.geometry("720x480")
        self.resizable(False, False)
        
        # Set dark theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        self._build_ui()
        self._setup_message_processor()
        
    def _build_ui(self) -> None:
        """Build the complete UI layout."""
        # Main container with padding
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left sidebar (control panel)
        left_sidebar = ctk.CTkFrame(main_container, width=150, fg_color="#1a1a1a", corner_radius=8)
        left_sidebar.pack(side="left", fill="y", padx=(0, 10))
        left_sidebar.pack_propagate(False)
        
        # Section title
        title_label = ctk.CTkLabel(
            left_sidebar,
            text="SCES CNS 3104",
            font=("Helvetica", 12, "bold"),
            text_color="#00FF7F"
        )
        title_label.pack(pady=(15, 25), padx=10)
        
        # Train button
        self.train_button = ctk.CTkButton(
            left_sidebar,
            text="🚀 Train System",
            command=self._on_train_clicked,
            fg_color="#2E7D32",
            hover_color="#1B5E20",
            text_color="white",
            font=("Helvetica", 11, "bold")
        )
        self.train_button.pack(pady=10, padx=10, fill="x")
        
        # Monitoring toggle
        monitoring_label = ctk.CTkLabel(
            left_sidebar,
            text="Live Monitoring",
            font=("Helvetica", 10, "bold"),
            text_color="#FFFFFF"
        )
        monitoring_label.pack(pady=(20, 8), padx=10)
        
        self.monitor_switch = ctk.CTkSwitch(
            left_sidebar,
            text="",
            command=self._on_monitor_toggle,
            onvalue=True,
            offvalue=False,
            button_color="#2E7D32",
            progress_color="#1B5E20"
        )
        self.monitor_switch.pack(pady=5, padx=10, fill="x")
        self.monitor_switch.deselect()
        
        # Status label
        status_label = ctk.CTkLabel(
            left_sidebar,
            text="Status",
            font=("Helvetica", 10, "bold"),
            text_color="#FFFFFF"
        )
        status_label.pack(pady=(20, 5), padx=10)
        
        self.status_label = ctk.CTkLabel(
            left_sidebar,
            text="IDLE",
            font=("Helvetica", 11, "bold"),
            text_color="#FFD700",
            corner_radius=4,
            fg_color="#2a2a2a"
        )
        self.status_label.pack(pady=5, padx=10, fill="x")
        
        # Right section (logging console)
        right_section = ctk.CTkFrame(main_container, fg_color="transparent")
        right_section.pack(side="right", fill="both", expand=True)
        
        console_title = ctk.CTkLabel(
            right_section,
            text="System Log",
            font=("Helvetica", 11, "bold"),
            text_color="#FFFFFF"
        )
        console_title.pack(pady=(0, 5), padx=10)
        
        # Console textbox
        self.console = ctk.CTkTextbox(
            right_section,
            font=("Courier New", 9),
            fg_color="#0a0a0a",
            text_color="#00FF00",
            corner_radius=6,
            border_width=1,
            border_color="#333333"
        )
        self.console.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.console.configure(state="normal")
        
        # Clear button
        clear_button = ctk.CTkButton(
            right_section,
            text="Clear Log",
            command=self._clear_console,
            fg_color="#555555",
            hover_color="#666666",
            text_color="white",
            font=("Helvetica", 9)
        )
        clear_button.pack(side="left", padx=10, pady=(0, 10))
        
        # Initialize detector
        self.detector = DetectionEngine(self.db, log_callback=self._log_message)
        self._log_message("System initialized and ready")
        
    def _setup_message_processor(self) -> None:
        """Set up periodic processing of message queue for thread-safe UI updates."""
        self.process_queue()
    
    def process_queue(self) -> None:
        """Process all pending messages from the queue and update UI."""
        try:
            while True:
                message = self.message_queue.get_nowait()
                self._append_to_console(message)
        except queue.Empty:
            pass
        
        # Schedule next check
        self.after(100, self.process_queue)
    
    def _log_message(self, message: str) -> None:
        """
        Thread-safe message logging via queue.
        
        Args:
            message: Message to log
        """
        self.message_queue.put(message)
    
    def _append_to_console(self, message: str) -> None:
        """
        Append message to console textbox.
        
        Args:
            message: Message to append
        """
        self.console.configure(state="normal")
        self.console.insert("end", message + "\n")
        self.console.see("end")
        self.console.configure(state="disabled")
    
    def _clear_console(self) -> None:
        """Clear all text from console."""
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
    
    def _on_train_clicked(self) -> None:
        """Handle train button click."""
        if self.training_active:
            self._log_message("⚠ Training already in progress")
            return
        
        if self.monitoring_active:
            self._log_message("⚠ Cannot train while monitoring is active")
            return
        
        self.training_active = True
        self._update_status("TRAINING")
        self.train_button.configure(state="disabled")
        
        # Run training in daemon thread
        train_thread = threading.Thread(target=self._train_worker, daemon=True)
        train_thread.start()
    
    def _train_worker(self) -> None:
        """Worker thread for training operation."""
        try:
            networks = self.detector.perform_training(scan_count=3)
            self.db.save_baseline(networks)
            self._log_message(f"✓ Training complete: {len(networks)} networks saved as baseline")
        except Exception as e:
            self._log_message(f"✗ Training error: {e}")
        finally:
            self.training_active = False
            self._update_status("IDLE")
            self.train_button.configure(state="normal")
    
    def _on_monitor_toggle(self) -> None:
        """Handle monitoring switch toggle."""
        if self.monitor_switch.get():
            self._start_monitoring()
        else:
            self._stop_monitoring()
    
    def _start_monitoring(self) -> None:
        """Start continuous monitoring in background thread."""
        if self.training_active:
            self._log_message("⚠ Cannot start monitoring while training")
            self.monitor_switch.deselect()
            return
        
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self._update_status("ACTIVE GUARD")
        self._log_message("▶ Live monitoring started (8-second interval)")
        
        # Create stop event for this monitoring session
        self.monitor_stop_event = threading.Event()
        
        # Run monitoring in daemon thread
        self.monitor_thread = threading.Thread(
            target=self.detector.continuous_monitor,
            kwargs={
                "interval_seconds": 8,
                "stop_event": self.monitor_stop_event,
                "alert_callback": self._on_security_alert
            },
            daemon=True
        )
        self.monitor_thread.start()
    
    def _stop_monitoring(self) -> None:
        """Stop continuous monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        if self.monitor_stop_event:
            self.monitor_stop_event.set()
        
        self._log_message("■ Monitoring stopped")
        self._update_status("IDLE")
    
    def _on_security_alert(self, ssid: str, bssid: str, alert_type: str) -> None:
        """
        Handle security alerts.
        
        Args:
            ssid: Network SSID
            bssid: Network BSSID
            alert_type: Type of alert (UNAUTHORIZED_BSSID, SECURITY_DOWNGRADE)
        """
        alert_messages = {
            "UNAUTHORIZED_BSSID": f"🚨 Evil Twin Alert: Unauthorized BSSID for '{ssid}'",
            "SECURITY_DOWNGRADE": f"⚠ Security Alert: Downgrade detected on '{ssid}'"
        }
        
        message = alert_messages.get(alert_type, f"🔔 Security Alert: {alert_type}")
        self._log_message(message)
        
        # Send Windows toast notification
        if self.toaster:
            try:
                self.toaster.show_toast(
                    title="Security Alert",
                    msg=message,
                    duration=10,
                    threaded=True
                )
            except Exception as e:
                self._log_message(f"Notification error: {e}")
    
    def _update_status(self, status: str) -> None:
        """
        Update status label.
        
        Args:
            status: Status text (IDLE, TRAINING, ACTIVE GUARD)
        """
        color_map = {
            "IDLE": "#FFD700",
            "TRAINING": "#FF6B6B",
            "ACTIVE GUARD": "#00FF7F"
        }
        self.status_label.configure(
            text=status,
            text_color=color_map.get(status, "#FFFFFF")
        )
    
    def on_closing(self) -> None:
        """Handle application window closing."""
        self._stop_monitoring()
        self._log_message("System shutting down...")
        self.after(200, self.destroy)
    
    def run(self) -> None:
        """Start the application event loop."""
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.mainloop()
