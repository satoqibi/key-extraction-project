import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import queue
import os
import signal

# The name of your main listener script
LISTENER_SCRIPT_PATH = "listener.py"

class SshDecryptorGui(tk.Tk):
    """
    A Tkinter GUI to start, stop, and monitor the output of the SSH decryption script.
    """
    def __init__(self):
        super().__init__()
        self.title("SSH Session Decryptor")
        self.geometry("850x650")

        self.process = None
        self.monitor_thread = None
        self.log_queue = queue.Queue()

        self.create_widgets()
        # Ensure graceful shutdown on window close
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """Creates and arranges the GUI widgets."""
        # --- Main frame ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)

        # --- Control section ---
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(side="top", fill="x", pady=(0, 10))

        self.start_button = ttk.Button(control_frame, text="▶ Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=(0, 5))

        self.stop_button = ttk.Button(control_frame, text="■ Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        info_label = ttk.Label(control_frame,
            text="Note: Configure paths and interface directly in listener.py",
            font=("TkDefaultFont", 9, "italic"))
        info_label.pack(side="right")

        # --- Log output section ---
        log_label = ttk.Label(main_frame, text="Live Output Log", font=("TkDefaultFont", 10, "bold"))
        log_label.pack(side="top", anchor="w")

        self.log_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state="disabled", bg="#f0f0f0", relief="solid", borderwidth=1)
        self.log_widget.pack(fill="both", expand=True)

    def update_log_widget(self):
        """Checks the queue for new log messages and updates the text widget."""
        while not self.log_queue.empty():
            try:
                message = self.log_queue.get_nowait()
                self.log_widget.config(state="normal")
                self.log_widget.insert(tk.END, message)
                self.log_widget.see(tk.END)  # Auto-scroll to the end
                self.log_widget.config(state="disabled")
            except queue.Empty:
                pass
        # Reschedule itself to run again after 100ms
        self.after(100, self.update_log_widget)

    def start_monitoring(self):
        """Starts the listener.py script in a separate thread."""
        if not os.path.exists(LISTENER_SCRIPT_PATH):
            messagebox.showerror("Error", f"Listener script not found: {LISTENER_SCRIPT_PATH}")
            return

        self.log_widget.config(state="normal")
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.insert(tk.END, "🚀 Starting monitoring process...\n")
        self.log_widget.insert(tk.END, "🔑 You may be prompted for your 'sudo' password in the terminal.\n\n")
        self.log_widget.config(state="disabled")

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        # Run the subprocess handling in a separate thread to keep the GUI responsive
        self.monitor_thread = threading.Thread(target=self._run_subprocess, daemon=True)
        self.monitor_thread.start()

        # Start the periodic check for new log messages from the thread
        self.update_log_widget()

    def _run_subprocess(self):
        """Executes the listener script and pipes its output to the log queue."""
        try:
            command = ['sudo', 'python3', LISTENER_SCRIPT_PATH]
            # Use preexec_fn=os.setsid to create a new process group.
            # This allows sending a signal to the entire group (sudo + python).
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Redirect stderr to stdout to capture all output
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,  # Line-buffered
                preexec_fn=os.setsid
            )

            # Read output line by line in real-time
            for line in iter(self.process.stdout.readline, ''):
                self.log_queue.put(line)

            self.process.stdout.close()
            return_code = self.process.wait()
            self.log_queue.put(f"\n--- ✅ Process finished with exit code {return_code} ---\n")

        except FileNotFoundError:
            self.log_queue.put("Error: 'sudo' or 'python3' not found. Ensure they are in your system's PATH.\n")
        except Exception as e:
            self.log_queue.put(f"An unexpected error occurred: {e}\n")
        finally:
            # Schedule the GUI state reset on the main thread
            self.after(0, self.on_process_finished)

    def stop_monitoring(self):
        """Stops the running subprocess by sending a SIGINT signal."""
        if self.process and self.process.poll() is None:  # Check if process is running
            self.log_queue.put("\n--- 🛑 Sending stop signal (SIGINT)... ---\n")
            try:
                # Send SIGINT to the entire process group
                os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            except ProcessLookupError:
                self.log_queue.put("--- Process already terminated. ---\n")
            except Exception as e:
                self.log_queue.put(f"--- Error sending signal: {e} ---\n")
        else:
            self.log_queue.put("--- Process is not running. ---\n")

        self.stop_button.config(state="disabled")

    def on_process_finished(self):
        """Callback to reset the GUI state after the process has terminated."""
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.process = None

    def on_closing(self):
        """Handles the window close ('X') button event."""
        if self.process and self.process.poll() is None:
            if messagebox.askokcancel("Quit", "The monitoring process is running. Stop it and exit?"):
                self.stop_monitoring()
                # Give the process a moment to shut down before destroying the window
                self.after(500, self.destroy)
            else:
                return  # Do not close the window if user cancels
        self.destroy()

if __name__ == "__main__":
    app = SshDecryptorGui()
    app.mainloop()