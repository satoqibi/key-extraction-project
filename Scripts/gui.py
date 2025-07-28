import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import queue
import os
import signal
import time
import sys

# --- CONFIGURATION ---
# The listener script to run
LISTENER_SCRIPT_NAME = "listener.py"
# The log file that the listener script writes to
LOG_FILE_TO_MONITOR = "/tmp/file.log"
# ---------------------

class SimpleLogViewer(tk.Tk):
    """
    A simple GUI to start a script and tail its log file.
    """
    def __init__(self):
        super().__init__()
        self.title("SSH Decryptor Log Viewer")
        self.geometry("800x600")

        self.process = None
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.monitor_thread = None

        self.create_widgets()
        self.periodic_log_check()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)

        # --- Controls ---
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill="x", pady=5)
        self.start_button = ttk.Button(controls_frame, text="▶ Start & View Logs", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=(0, 10))
        self.stop_button = ttk.Button(controls_frame, text="■ Stop Listener", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left")

        # --- Log Viewer ---
        log_frame = ttk.LabelFrame(main_frame, text=f"Monitoring: {LOG_FILE_TO_MONITOR}", padding="10")
        log_frame.pack(fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="black", fg="lightgreen", insertbackground="white")
        self.log_text.pack(fill="both", expand=True)

    def periodic_log_check(self):
        """Safely updates the GUI text widget from the log queue."""
        while not self.log_queue.empty():
            line = self.log_queue.get_nowait()
            self.log_text.insert(tk.END, line)
            self.log_text.see(tk.END)
        self.after(100, self.periodic_log_check)

    def start_monitoring(self):
        """Starts the listener.py subprocess and the log tailing thread."""
        if not os.path.exists(LISTENER_SCRIPT_NAME):
            messagebox.showerror("Error", f"Could not find '{LISTENER_SCRIPT_NAME}'")
            return

        # Clean up the old log file to ensure a fresh start
        if os.path.exists(LOG_FILE_TO_MONITOR):
            try:
                os.remove(LOG_FILE_TO_MONITOR)
            except OSError as e:
                messagebox.showerror("File Error", f"Could not remove old log file:\n{e}\n\nPlease remove it manually:\nsudo rm {LOG_FILE_TO_MONITOR}")
                return

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.log_text.delete('1.0', tk.END)
        self.stop_event.clear()

        # Start both the subprocess and the log tailer in a single management thread
        self.monitor_thread = threading.Thread(target=self._run_and_tail, daemon=True)
        self.monitor_thread.start()

    def _run_and_tail(self):
        """Runs the listener.py subprocess and starts tailing its log file."""
        try:
            # Launch the listener.py script
            python_executable = sys.executable
            command = [python_executable, '-u',  LISTENER_SCRIPT_NAME]
            self.process = subprocess.Popen(command)
            self.log_queue.put(f"🚀 Started '{LISTENER_SCRIPT_NAME}' (PID: {self.process.pid}).\n")
            
            # Start tailing the log file
            self._tail_log_file()
            
            # Wait for the process to end
            self.process.wait()
            
        except Exception as e:
            self.log_queue.put(f"💥 Error launching subprocess: {e}\n")
        finally:
            self.log_queue.put("\n--- ✅ Backend process finished. ---\n")
            self.after(0, self.on_monitoring_stopped) # Schedule GUI update on main thread

    def _tail_log_file(self):
        """Opens the log file and watches for new lines."""
        self.log_queue.put("Waiting for log file to be created...\n")
        while not os.path.exists(LOG_FILE_TO_MONITOR):
            if self.stop_event.is_set(): return
            time.sleep(0.5)

        self.log_queue.put(f"Tailing log file: {LOG_FILE_TO_MONITOR}\n\n")
        try:
            with open(LOG_FILE_TO_MONITOR, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(0, 2)
                while not self.stop_event.is_set():
                    line = f.readline()
                    if line:
                        self.log_queue.put(line)
                    else:
                        time.sleep(0.1)
        except Exception as e:
            self.log_queue.put(f"Error tailing log file: {e}\n")

    def stop_monitoring(self):
        """Sends a stop signal to the listener.py process."""
        self.stop_button.config(state="disabled")
        self.stop_event.set()
        
        if self.process and self.process.poll() is None:
            self.log_queue.put("\n--- 🛑 Sending stop signal (Ctrl+C) to backend... ---\n")
            try:
                os.kill(self.process.pid, signal.SIGINT)
            except (ProcessLookupError, PermissionError) as e:
                self.log_queue.put(f"--- Could not send signal: {e} ---\n")
        else:
            self.on_monitoring_stopped()

    def on_monitoring_stopped(self):
        """Resets the GUI state."""
        self.start_button.config(state="normal")
        self.stop_event.set()

    def on_closing(self):
        """Handles the window close event."""
        self.stop_monitoring()
        self.destroy()

if __name__ == "__main__":
    app = SimpleLogViewer()
    app.mainloop()
