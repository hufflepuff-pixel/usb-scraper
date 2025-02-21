import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import usb.core
import usb.util
import os
import shutil
import logging
import sys
from pathlib import Path
from brand_lookup import get_brand_name
from datetime import datetime
from cve_database import scan_for_cve, generate_cve_report

class DebugWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Debug Console")
        self.geometry("600x400")
        self.configure(bg='#1e1e1e')

        # Create text widget for debug output
        self.text_widget = tk.Text(self, bg='#1e1e1e', fg='#ffffff', wrap=tk.WORD)
        self.text_widget.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Create scrollbar
        scrollbar = tk.Scrollbar(self.text_widget)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure text widget with scrollbar
        self.text_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.text_widget.yview)
        
        # Add clear button
        clear_button = tk.Button(self, text="Clear Log", command=self.clear_log,
                               bg="#2d2d2d", fg="white", relief="flat")
        clear_button.pack(pady=5)

    def log(self, message):
        """Add message to debug window with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        self.text_widget.insert(tk.END, f"[{timestamp}] {message}\n")
        self.text_widget.see(tk.END)
        
    def clear_log(self):
        """Clear the debug window"""
        self.text_widget.delete(1.0, tk.END)

class USBDebugger:
    def __init__(self, debug_window):
        self.debug_window = debug_window
        
    def log_device_info(self, device):
        """Log detailed USB device information"""
        try:
            self.debug_window.log(f"\n=== Device Information ===")
            self.debug_window.log(f"Vendor ID: {hex(device.idVendor)}")
            self.debug_window.log(f"Product ID: {hex(device.idProduct)}")
            
            try:
                # Get device configuration
                cfg = device.get_active_configuration()
                self.debug_window.log(f"Active Configuration: {cfg.bConfigurationValue}")
                
                # Log interface information
                for interface in cfg:
                    self.debug_window.log(f"\nInterface {interface.bInterfaceNumber}:")
                    self.debug_window.log(f"  Class: {interface.bInterfaceClass}")
                    self.debug_window.log(f"  Subclass: {interface.bInterfaceSubClass}")
                    self.debug_window.log(f"  Protocol: {interface.bInterfaceProtocol}")
                    
                    # Log endpoint information
                    for endpoint in interface:
                        self.debug_window.log(f"  Endpoint {endpoint.bEndpointAddress}:")
                        self.debug_window.log(f"    Type: {endpoint.bmAttributes}")
                        self.debug_window.log(f"    Max Packet Size: {endpoint.wMaxPacketSize}")
            
            except usb.core.USBError as e:
                self.debug_window.log(f"Could not get full configuration: {str(e)}")
            
            # Try to get string descriptors
            try:
                self.debug_window.log("\nDevice Descriptors:")
                if device.iManufacturer:
                    manufacturer = usb.util.get_string(device, device.iManufacturer)
                    self.debug_window.log(f"Manufacturer: {manufacturer}")
                if device.iProduct:
                    product = usb.util.get_string(device, device.iProduct)
                    self.debug_window.log(f"Product: {product}")
                if device.iSerialNumber:
                    serial = usb.util.get_string(device, device.iSerialNumber)
                    self.debug_window.log(f"Serial Number: {serial}")
            except:
                self.debug_window.log("Could not get string descriptors")
                
        except Exception as e:
            self.debug_window.log(f"Error getting device info: {str(e)}")
            
    def log_recovery_check(self, vendor_id, product_id):
        """Log recovery mode check results"""
        self.debug_window.log(f"\nChecking Recovery Mode:")
        self.debug_window.log(f"Device ID: {hex(vendor_id)}:{hex(product_id)}")
        
        # Check against known recovery mode IDs
        recovery_modes = {
            (0x05AC, 0x1281): "iPhone Recovery",
            (0x05AC, 0x1227): "iPad Recovery",
            (0x05AC, 0x1222): "Apple Device Recovery",
            (0x05AC, 0x1338): "Apple Mobile Device Recovery",
            (0x05AC, 0x1220): "Apple DFU Mode",
            (0x18D1, 0x4EE0): "Android Fastboot",
            (0x18D1, 0x4EE2): "Android Recovery",
            (0x18D1, 0xD001): "Android Download",
            (0x04E8, 0x6601): "Samsung Download",
            (0x04E8, 0x685D): "Samsung Recovery"
        }
        
        device_key = (vendor_id, product_id)
        if device_key in recovery_modes:
            self.debug_window.log(f"MATCH: {recovery_modes[device_key]}")
        else:
            self.debug_window.log("No recovery mode match found")

def find_usb_devices(debug_window=None):
    """Finds and returns a list of connected USB devices with debug output."""
    devices = []
    if debug_window:
        debugger = USBDebugger(debug_window)
        debug_window.log("\nScanning for USB devices...")
    
    try:
        for device in usb.core.find(find_all=True):
            try:
                if debug_window:
                    debug_window.log("\nFound USB device:")
                    debugger.log_device_info(device)
                
                vendor_id = device.idVendor
                product_id = device.idProduct
                
                if debug_window:
                    debugger.log_recovery_check(vendor_id, product_id)
                
                # Check for recovery mode identifiers
                is_recovery = False
                try:
                    # Expanded recovery mode checks
                    recovery_modes = {
                        (0x05AC, 0x1281): "iPhone Recovery Mode",
                        (0x05AC, 0x1227): "iPad Recovery Mode",
                        (0x05AC, 0x1222): "Apple Device Recovery Mode",
                        (0x05AC, 0x1338): "Apple Mobile Device (Recovery Mode)",
                        (0x05AC, 0x1220): "Apple Device DFU Mode",
                        (0x18D1, 0x4EE0): "Android Device (Fastboot)",
                        (0x18D1, 0x4EE2): "Android Device (Recovery)",
                        (0x18D1, 0xD001): "Android Device (Download)",
                        (0x04E8, 0x6601): "Samsung Device (Download Mode)",
                        (0x04E8, 0x685D): "Samsung Device (Recovery Mode)"
                    }
                    
                    device_key = (vendor_id, product_id)
                    if device_key in recovery_modes:
                        device_name = recovery_modes[device_key]
                        is_recovery = True
                    else:
                        device_name = get_brand_name(vendor_id, product_id)
                    
                    try:
                        cfg = device.get_active_configuration()
                        if cfg and is_recovery:
                            device_name += " (Connected)"
                    except:
                        if is_recovery:
                            device_name += " (Detected)"
                    
                    devices.append((device_name, device, is_recovery))
                    
                    if debug_window:
                        debug_window.log(f"Added device to list: {device_name}")
                
                except usb.core.USBError as e:
                    if debug_window:
                        debug_window.log(f"USB Error: {str(e)}")
                    continue
                    
            except Exception as e:
                if debug_window:
                    debug_window.log(f"Error processing device: {str(e)}")
                
    except Exception as e:
        if debug_window:
            debug_window.log(f"Error scanning USB devices: {str(e)}")
    
    if debug_window:
        debug_window.log(f"\nTotal devices found: {len(devices)}")
    
    return devices

def connect_recovery_device(device):
    """Attempts to connect to a device in recovery mode."""
    try:
        # Reset the device
        device.reset()
        
        # Set configuration
        device.set_configuration()
        
        # Find the first interface
        interface = 0
        
        # Try to claim the interface
        if device.is_kernel_driver_active(interface):
            device.detach_kernel_driver(interface)
        
        usb.util.claim_interface(device, interface)
        
        return True
    except usb.core.USBError as e:
        messagebox.showerror("Error", f"Failed to connect to recovery device: {str(e)}")
        return False

def handle_device_selection(event=None):
    """Handles device selection from dropdown, with special handling for recovery mode."""
    selected_device_name = device_dropdown.get()
    selected_device = next((device for name, device, is_recovery in usb_devices if name == selected_device_name), None)
    selected_recovery = next((is_recovery for name, device, is_recovery in usb_devices if name == selected_device_name), False)
    
    if selected_device and selected_recovery:
        if connect_recovery_device(selected_device):
            messagebox.showinfo("Success", "Successfully connected to device in recovery mode")
            execute_operation_button.config(state="normal")
        else:
            execute_operation_button.config(state="disabled")
    else:
        execute_operation_button.config(state="normal")

def bruteforce_operation(source_path, dest_path, progress_bar, root):
    """Executes a brute force copy operation with detailed progress."""
    try:
        total_files = sum([len(files) for _, _, files in os.walk(source_path)])
        copied_files = 0
        
        for root_dir, _, files in os.walk(source_path):
            rel_path = os.path.relpath(root_dir, source_path)
            dest_dir = os.path.join(dest_path, rel_path)
            os.makedirs(dest_dir, exist_ok=True)
            
            for file in files:
                src_file = os.path.join(root_dir, file)
                dst_file = os.path.join(dest_dir, file)
                
                attempt = 0
                max_attempts = 5
                while attempt < max_attempts:
                    try:
                        sub_progress = (attempt / max_attempts) * (100 / total_files)
                        current_progress = (copied_files * (100 / total_files)) + sub_progress
                        progress_bar['value'] = current_progress
                        root.update_idletasks()
                        
                        shutil.copy2(src_file, dst_file)
                        break
                    except PermissionError:
                        attempt += 1
                        root.after(100)
                        continue
                    except Exception as e:
                        raise e
                
                copied_files += 1
                progress = (copied_files / total_files) * 100
                progress_bar['value'] = progress
                root.update_idletasks()
        
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Brute force operation failed: {str(e)}")
        return False

def inject_operation(source_path, dest_path, progress_bar, root):
    """Executes an inject operation with detailed progress."""
    try:
        if os.path.isfile(source_path):
            stages = ['Preparing', 'Injecting', 'Verifying']
            for i, stage in enumerate(stages):
                progress = ((i + 1) / len(stages)) * 100
                progress_bar['value'] = progress
                root.update_idletasks()
                root.after(500)
                
            shutil.copy2(source_path, dest_path)
        else:
            total_files = sum([len(files) for _, _, files in os.walk(source_path)])
            copied_files = 0
            
            for root_dir, _, files in os.walk(source_path):
                rel_path = os.path.relpath(root_dir, source_path)
                dest_dir = os.path.join(dest_path, rel_path)
                os.makedirs(dest_dir, exist_ok=True)
                
                for file in files:
                    src_file = os.path.join(root_dir, file)
                    dst_file = os.path.join(dest_dir, file)
                    
                    progress_per_file = 100 / total_files
                    stages = ['Analyzing', 'Injecting', 'Verifying']
                    
                    for i, stage in enumerate(stages):
                        stage_progress = (i / len(stages)) * progress_per_file
                        current_progress = (copied_files * progress_per_file) + stage_progress
                        progress_bar['value'] = current_progress
                        root.update_idletasks()
                        root.after(100)
                    
                    shutil.copy2(src_file, dst_file)
                    copied_files += 1
                    
                    progress = (copied_files / total_files) * 100
                    progress_bar['value'] = progress
                    root.update_idletasks()
        
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Inject operation failed: {str(e)}")
        return False

def exfiltrate_operation(source_path, dest_path, progress_bar, root):
    """Executes a data exfiltration operation with detailed progress."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{timestamp}"
        backup_path = os.path.join(dest_path, backup_name)
        
        progress_bar['value'] = 5
        root.update_idletasks()
        os.makedirs(backup_path, exist_ok=True)
        
        total_files = sum([len(files) for _, _, files in os.walk(source_path)])
        copied_files = 0
        
        progress_bar['value'] = 10
        root.update_idletasks()
        root.after(300)
        
        for root_dir, _, files in os.walk(source_path):
            rel_path = os.path.relpath(root_dir, source_path)
            dest_dir = os.path.join(backup_path, rel_path)
            os.makedirs(dest_dir, exist_ok=True)
            
            for file in files:
                src_file = os.path.join(root_dir, file)
                dst_file = os.path.join(dest_dir, file)
                
                stages = ['Reading', 'Copying', 'Verifying']
                progress_per_file = 90 / total_files
                
                for i, stage in enumerate(stages):
                    stage_progress = (i / len(stages)) * progress_per_file
                    current_progress = 10 + (copied_files * progress_per_file) + stage_progress
                    progress_bar['value'] = current_progress
                    root.update_idletasks()
                    root.after(50)
                
                shutil.copy2(src_file, dst_file)
                copied_files += 1
                
                progress = 10 + (copied_files / total_files) * 90
                progress_bar['value'] = progress
                root.update_idletasks()
        
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Data exfiltration operation failed: {str(e)}")
        return False

def sync_operation(source_path, dest_path, progress_bar, root):
    """Executes a sync operation with detailed progress."""
    try:
        progress_bar['value'] = 5
        root.update_idletasks()
        root.after(200)
        
        source_files = {}
        dest_files = {}
        
        progress_bar['value'] = 10
        root.update_idletasks()
        for root_dir, _, files in os.walk(source_path):
            for file in files:
                full_path = os.path.join(root_dir, file)
                rel_path = os.path.relpath(full_path, source_path)
                source_files[rel_path] = os.path.getmtime(full_path)
        
        progress_bar['value'] = 20
        root.update_idletasks()
        for root_dir, _, files in os.walk(dest_path):
            for file in files:
                full_path = os.path.join(root_dir, file)
                rel_path = os.path.relpath(full_path, dest_path)
                dest_files[rel_path] = os.path.getmtime(full_path)
        
        progress_bar['value'] = 30
        root.update_idletasks()
        root.after(200)
        
        all_files = set(source_files.keys()) | set(dest_files.keys())
        total_operations = len(all_files)
        completed_operations = 0
        
        for file in all_files:
            source_file = os.path.join(source_path, file)
            dest_file = os.path.join(dest_path, file)
            
            stages = ['Comparing', 'Syncing', 'Verifying']
            progress_per_file = 70 / total_operations
            
            for i, stage in enumerate(stages):
                stage_progress = (i / len(stages)) * progress_per_file
                current_progress = 30 + (completed_operations * progress_per_file) + stage_progress
                progress_bar['value'] = current_progress
                root.update_idletasks()
                root.after(50)
            
            os.makedirs(os.path.dirname(dest_file), exist_ok=True)
            
            if file in source_files and file in dest_files:
                if source_files[file] > dest_files[file]:
                    shutil.copy2(source_file, dest_file)
                elif dest_files[file] > source_files[file]:
                    shutil.copy2(dest_file, source_file)
            elif file in source_files:
                shutil.copy2(source_file, dest_file)
            else:
                shutil.copy2(dest_file, source_file)
            
            completed_operations += 1
            progress = 30 + (completed_operations / total_operations) * 70
            progress_bar['value'] = progress
            root.update_idletasks()
        
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Sync operation failed: {str(e)}")
        return False

def copy_files_from_device(device_name, save_path, progress_bar, root):
    """Copies files from the connected USB device to a folder."""
    try:
        debug_window.log(f"Creating folder on desktop for device: {device_name}")
        desktop_path = Path.home() / "Desktop" / device_name
        desktop_path.mkdir(exist_ok=True)
        
        if os.path.exists(save_path):
            files = os.listdir(save_path)
            total_files = len(files)
            debug_window.log(f"Found {total_files} files to copy")
            
            for index, item in enumerate(files):
                source = os.path.join(save_path, item)
                destination = os.path.join(desktop_path, item)
                try:
                    if os.path.isfile(source):
                        debug_window.log(f"Copying file: {item}")
                        shutil.copy2(source, destination)
                    progress_bar['value'] = (index + 1) / total_files * 100
                    root.update_idletasks()
                except Exception as e:
                    debug_window.log(f"Error copying file {item}: {str(e)}")
        
        debug_window.log(f"Files copied successfully to {desktop_path}")
        messagebox.showinfo("Success", f"Files copied to {desktop_path}")
    except Exception as e:
        debug_window.log(f"Error in copy process: {str(e)}")
        messagebox.showerror("Error", f"Copy process failed: {str(e)}")

def add_files_to_device(device_path, files, progress_bar, root):
    """Adds files to the connected USB device."""
    try:
        if not os.path.exists(device_path):
            debug_window.log("Error: Device storage not accessible")
            messagebox.showerror("Error", "Device storage not accessible.")
            return
        
        total_files = len(files)
        debug_window.log(f"Attempting to add {total_files} files to device")
        
        for index, file in enumerate(files):
            try:
                source = Path(file.strip())
                destination = Path(device_path) / source.name
                
                if source.exists():
                    debug_window.log(f"Copying file: {source.name}")
                    shutil.copy2(source, destination)
                    progress_bar['value'] = (index + 1) / total_files * 100
                    root.update_idletasks()
                else:
                    debug_window.log(f"File not found: {source}")
                    messagebox.showerror("Error", f"File not found: {source}")
            except Exception as e:
                debug_window.log(f"Error copying file {file}: {str(e)}")
                messagebox.showerror("Error", f"Failed to copy {file}: {str(e)}")
        
        debug_window.log("Files added successfully to device")
        messagebox.showinfo("Success", "Files added to the device.")
    except Exception as e:
        debug_window.log(f"Error in add files process: {str(e)}")
        messagebox.showerror("Error", f"Add files process failed: {str(e)}")

def scan_device_for_issues(device_name, device_path, progress_bar, root):
    """Scans the connected USB device for security issues."""
    try:
        total_scanned = 0
        issues_found = []
        autorun_files = []
        cve_findings = []  # New list for CVE findings
        
        total_files = sum([len(files) for _, _, files in os.walk(device_path)])
        
        for root_dir, _, files in os.walk(device_path):
            for filename in files:
                file_path = os.path.join(root_dir, filename)
                
                # Existing checks
                if filename.lower() in ['autorun.inf', 'desktop.ini', 'thumbs.db']:
                    autorun_files.append(filename)
                    
                if filename.lower().endswith(('.exe', '.dll', '.sys', '.bat', '.vbs', '.ps1')):
                    issues_found.append(f"Executable file found: {filename}")
                    
                # New CVE scan
                matched_cves = scan_for_cve(filename)
                if matched_cves:
                    cve_report = generate_cve_report(filename, matched_cves)
                    cve_findings.append(cve_report)
                    
                try:
                    if os.access(file_path, os.X_OK):
                        issues_found.append(f"File with execute permissions: {filename}")
                except Exception:
                    pass
                    
                total_scanned += 1
                if total_files > 0:
                    progress = (total_scanned / total_files) * 100
                    progress_bar['value'] = progress
                    root.update_idletasks()
        
        # Updated reporting to include CVE findings
        if issues_found or autorun_files or cve_findings:
            message = f"Issues found on device {device_name}:\n\n"
            
            if autorun_files:
                message += "Autorun files found:\n"
                message += "\n".join(f"- {file}" for file in autorun_files)
                message += "\n\n"
                
            if issues_found:
                message += "Potential security concerns:\n"
                message += "\n".join(f"- {issue}" for issue in issues_found)
                message += "\n\n"
                
            if cve_findings:
                message += "CVE Vulnerabilities Found:\n"
                message += "\n".join(cve_findings)
                
            messagebox.showwarning("Scan Results", message)
            
            # Log findings to debug window
            debug_window.log("CVE Scan completed")
            for finding in cve_findings:
                debug_window.log(finding)
        else:
            messagebox.showinfo("Scan Complete", f"No security issues found on device {device_name}")
            
    except Exception as e:
        messagebox.showerror("Error", f"Scan failed: {str(e)}")

def get_save_path_from_dropdown(dropdown_value):
    """Returns the path based on the dropdown selection."""
    if dropdown_value == 'System Files':
        return Path("/etc")
    elif dropdown_value == 'Downloads':
        return Path.home() / "Downloads"
    elif dropdown_value == 'Documents':
        return Path.home() / "Documents"
    elif dropdown_value == 'Desktop':
        return Path.home() / "Desktop"
    elif dropdown_value == 'Custom':
        custom_path = custom_path_entry.get()
        if not custom_path:
            messagebox.showerror("Error", "Please enter a valid path.")
            return None
        return Path(custom_path)
    return None

def start_scan_process():
    """Starts the device scanning process."""
    selected_device_name = device_dropdown.get()
    selected_device = next((device for name, device, is_recovery in usb_devices if name == selected_device_name), None)
    if not selected_device:
        messagebox.showerror("Error", "No device selected.")
        return
    
    save_path = get_save_path_from_dropdown(save_location.get())
    if not save_path:
        return

    debug_window.log(f"Starting scan process for device: {selected_device_name}")
    scan_device_for_issues(selected_device_name, save_path, progress_bar, root)

def start_copy_process():
    """Starts the copy process."""
    selected_device_name = device_dropdown.get()
    selected_device = next((device for name, device, is_recovery in usb_devices if name == selected_device_name), None)
    if not selected_device:
        messagebox.showerror("Error", "No device selected.")
        return
    
    save_path = get_save_path_from_dropdown(save_location.get())
    if not save_path:
        return

    debug_window.log(f"Starting copy process for device: {selected_device_name}")
    copy_files_from_device(selected_device_name, save_path, progress_bar, root)

def start_add_files_process():
    """Starts the process to add files to the device."""
    selected_device_name = device_dropdown.get()
    selected_device = next((device for name, device, is_recovery in usb_devices if name == selected_device_name), None)
    if not selected_device:
        messagebox.showerror("Error", "No device selected.")
        return
    
    save_path = get_save_path_from_dropdown(save_location.get())
    if not save_path:
        return
    
    file_list = file_paths_entry.get().split(',')
    debug_window.log(f"Adding files to device: {selected_device_name}")
    add_files_to_device(save_path, file_list, progress_bar, root)

def open_file_dialog():
    """Opens a file dialog to select files."""
    files = filedialog.askopenfilenames(title="Select Files to Add")
    file_paths_entry.delete(0, tk.END)
    file_paths_entry.insert(0, ', '.join(files))
    debug_window.log(f"Selected files: {files}")

def start_operation_process():
    """Starts the selected operation process."""
    selected_operation = operation_type.get()
    if selected_operation == "Select operation":
        messagebox.showerror("Error", "Please select an operation type.")
        return
        
    source_path = get_save_path_from_dropdown(save_location.get())
    if not source_path:
        return
        
    dest_path = Path(custom_path_entry.get()) if custom_path_entry.get() else Path.home() / "Desktop" / "USB_Operations"
    dest_path.mkdir(exist_ok=True)
    
    debug_window.log(f"Starting {selected_operation} operation")
    debug_window.log(f"Source path: {source_path}")
    debug_window.log(f"Destination path: {dest_path}")
    
    execute_operation(selected_operation, source_path, dest_path, progress_bar, root)

def refresh_devices():
    """Refresh the list of connected devices"""
    global usb_devices
    debug_window.log("Refreshing device list...")
    usb_devices = find_usb_devices(debug_window)
    device_names = [device_name for device_name, _, _ in usb_devices]
    device_dropdown['values'] = device_names
    debug_window.log("Device list refreshed")

def execute_operation(operation_type, source_path, dest_path, progress_bar, root):
    """Executes the selected operation type."""
    try:
        if not os.path.exists(source_path):
            messagebox.showerror("Error", "Source path does not exist.")
            return
            
        os.makedirs(dest_path, exist_ok=True)
        
        success = False
        if operation_type == "BruteForce":
            success = bruteforce_operation(source_path, dest_path, progress_bar, root)
        elif operation_type == "Inject":
            success = inject_operation(source_path, dest_path, progress_bar, root)
        elif operation_type == "Data exfiltration":
            success = exfiltrate_operation(source_path, dest_path, progress_bar, root)
        elif operation_type == "Sync":
            success = sync_operation(source_path, dest_path, progress_bar, root)
        
        if success:
            messagebox.showinfo("Success", f"{operation_type} operation completed successfully.")
        
    except Exception as e:
        messagebox.showerror("Error", f"Operation failed: {str(e)}")
    finally:
        progress_bar['value'] = 100
        root.update_idletasks()

# Added functions for .conf file search
def search_conf_files():
    """Searches for .conf files with the specified pattern"""
    selected_device_name = device_dropdown.get()
    if selected_device_name == "Select a device":
        messagebox.showerror("Error", "No device selected.")
        return
    
    search_pattern = conf_search_entry.get()
    if not search_pattern:
        messagebox.showerror("Error", "Please enter a search pattern for .conf files.")
        return
    
    save_path = get_save_path_from_dropdown(save_location.get())
    if not save_path:
        return
    
    debug_window.log(f"Starting search for .conf files with pattern: {search_pattern}")
    
    try:
        found_files = []
        total_dirs = sum([len(dirs) for _, dirs, _ in os.walk(save_path)])
        processed_dirs = 0
        
        progress_bar['value'] = 0
        root.update_idletasks()
        
        for root_dir, _, files in os.walk(save_path):
            processed_dirs += 1
            progress = (processed_dirs / max(1, total_dirs)) * 100
            progress_bar['value'] = progress
            root.update_idletasks()
            
            for filename in files:
                if filename.lower().endswith('.conf') and search_pattern.lower() in filename.lower():
                    file_path = os.path.join(root_dir, filename)
                    debug_window.log(f"Found matching .conf file: {file_path}")
                    found_files.append(file_path)
        
        progress_bar['value'] = 100
        root.update_idletasks()
        
        if found_files:
            debug_window.log(f"Found {len(found_files)} .conf files matching pattern.")
            display_conf_files(found_files)
        else:
            debug_window.log("No matching .conf files found.")
            messagebox.showinfo("Search Results", "No matching .conf files found.")
    
    except Exception as e:
        debug_window.log(f"Error searching for .conf files: {str(e)}")
        messagebox.showerror("Error", f"Search failed: {str(e)}")

def display_conf_files(file_paths):
    """Displays the search results in a new window"""
    result_window = tk.Toplevel(root)
    result_window.title("Config File Search Results")
    result_window.geometry("700x500")
    result_window.configure(bg='#1e1e1e')
    
    # Create frame for the results
    result_frame = tk.Frame(result_window, bg='#1e1e1e')
    result_frame.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Add label for results count
    header_label = tk.Label(result_frame, text=f"Found {len(file_paths)} .conf files:", 
                           bg='#1e1e1e', fg='white')
    header_label.pack(anchor='w', pady=(0, 10))
    
    # Create a listbox for results with scrollbar
    list_frame = tk.Frame(result_frame, bg='#1e1e1e')
    list_frame.pack(fill='both', expand=True)
    
    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    file_listbox = tk.Listbox(list_frame, bg='#2d2d2d', fg='white', width=80, height=20,
                             selectbackground='#4a4a4a', selectforeground='white',
                             yscrollcommand=scrollbar.set)
    file_listbox.pack(side=tk.LEFT, fill='both', expand=True)
    scrollbar.config(command=file_listbox.yview)
    
    # Add file paths to the listbox
    for file_path in file_paths:
        file_listbox.insert(tk.END, file_path)
    
    # Add buttons for actions
    button_frame = tk.Frame(result_window, bg='#1e1e1e')
    button_frame.pack(fill='x', padx=10, pady=10)
    
    def view_selected_file():
        selected_indices = file_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Please select a file to view.")
            return
        
        selected_file = file_listbox.get(selected_indices[0])
        try:
            view_window = tk.Toplevel(result_window)
            view_window.title(f"File Viewer - {os.path.basename(selected_file)}")
            view_window.geometry("800x600")
            view_window.configure(bg='#1e1e1e')
            
            # Create text widget with scrollbar for file content
            view_frame = tk.Frame(view_window, bg='#1e1e1e')
            view_frame.pack(fill='both', expand=True, padx=10, pady=10)
            
            view_scrollbar = tk.Scrollbar(view_frame)
            view_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            view_text = tk.Text(view_frame, bg='#2d2d2d', fg='white', wrap=tk.WORD,
                              yscrollcommand=view_scrollbar.set)
            view_text.pack(side=tk.LEFT, fill='both', expand=True)
            view_scrollbar.config(command=view_text.yview)
            
            # Read and display file content
            try:
                with open(selected_file, 'r') as f:
                    content = f.read()
                    view_text.insert(tk.END, content)
            except Exception as e:
                view_text.insert(tk.END, f"Error reading file: {str(e)}")
            
            # Make text read-only
            view_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to view file: {str(e)}")
    
    def copy_selected_file():
        selected_indices = file_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Please select a file to copy.")
            return
        
        selected_file = file_listbox.get(selected_indices[0])
        try:
            desktop_path = Path.home() / "Desktop"
            filename = os.path.basename(selected_file)
            destination = os.path.join(desktop_path, filename)
            
            shutil.copy2(selected_file, destination)
            messagebox.showinfo("Success", f"File copied to {destination}")
            debug_window.log(f"Copied .conf file to desktop: {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy file: {str(e)}")
    
    # Add action buttons
    view_button = tk.Button(button_frame, text="View File", command=view_selected_file,
                         bg="#2d2d2d", fg="white", relief="flat")
    view_button.pack(side=tk.LEFT, padx=5)
    
    copy_button = tk.Button(button_frame, text="Copy to Desktop", command=copy_selected_file,
                          bg="#2d2d2d", fg="white", relief="flat")
    copy_button.pack(side=tk.LEFT, padx=5)
    
    close_button = tk.Button(button_frame, text="Close", command=result_window.destroy,
                           bg="#2d2d2d", fg="white", relief="flat")
    close_button.pack(side=tk.RIGHT, padx=5)

# Initialize the GUI window
root = tk.Tk()
root.title("USB File Management")

# Set the window background to dark gray
root.configure(bg='#1e1e1e')

# Initialize debug window
debug_window = DebugWindow(root)
debug_window.geometry("+{}+{}".format(
    root.winfo_x() + root.winfo_width() + 10,
    root.winfo_y()
))

# First row: Device dropdown with recovery mode detection
usb_devices = find_usb_devices(debug_window)
device_names = [device_name for device_name, _, _ in usb_devices]
device_dropdown = ttk.Combobox(root, values=device_names, state="readonly")
device_dropdown.set("Select a device")
device_dropdown.grid(row=0, column=0, padx=10, pady=10)
device_dropdown.bind('<<ComboboxSelected>>', handle_device_selection)

# Add refresh button
refresh_button = tk.Button(root, text="Refresh Devices", command=refresh_devices,
                          bg="#2d2d2d", fg="white", relief="flat")
refresh_button.grid(row=0, column=2, padx=10, pady=10)

save_location = ttk.Combobox(root, values=["System Files", "Downloads", "Documents", "Desktop", "Custom"], state="readonly")
save_location.set("Select a location")
save_location.grid(row=0, column=1, padx=10, pady=10)

# Second row: New dropdown menu and custom path entry
operation_type = ttk.Combobox(root, values=["BruteForce", "Inject", "Data exfiltration", "Sync"], state="readonly")
operation_type.set("Select operation")
operation_type.grid(row=1, column=0, padx=10, pady=10)

custom_path_entry = tk.Entry(root)
custom_path_entry.grid(row=1, column=1, padx=10, pady=10)

# File paths entry for adding files
file_paths_label = tk.Label(root, text="Enter file paths (comma-separated):", fg="white", bg="#1e1e1e")
file_paths_label.grid(row=2, column=0, padx=10, pady=10)

file_paths_entry = tk.Entry(root)
file_paths_entry.grid(row=2, column=1, padx=10, pady=10)

# Button to open file dialog and add files
browse_button = tk.Button(root, text="Browse Files", command=open_file_dialog, bg="#2d2d2d", fg="white", relief="flat")
browse_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Add .conf file search section
conf_search_label = tk.Label(root, text="Search for .conf files:", fg="white", bg="#1e1e1e")
conf_search_label.grid(row=4, column=0, padx=10, pady=5, sticky='w')

conf_search_entry = tk.Entry(root, width=30)
conf_search_entry.grid(row=4, column=1, padx=10, pady=5, sticky='w')

conf_search_button = tk.Button(root, text="Search Config Files", command=search_conf_files,
                            bg="#2d2d2d", fg="white", relief="flat")
conf_search_button.grid(row=4, column=2, padx=10, pady=5)

# Progress bar
progress_bar = ttk.Progressbar(root, length=200, mode="determinate")
progress_bar.grid(row=5, column=0, columnspan=2, padx=10, pady=20)

# Buttons for starting the processes
scan_button = tk.Button(root, text="Scan Device for Issues", command=start_scan_process, bg="#2d2d2d", fg="white", relief="flat")
scan_button.grid(row=6, column=0, padx=10, pady=10)

copy_button = tk.Button(root, text="Copy Files from Device", command=start_copy_process, bg="#2d2d2d", fg="white", relief="flat")
copy_button.grid(row=6, column=1, padx=10, pady=10)

add_files_button = tk.Button(root, text="Add Files to Device", command=start_add_files_process, bg="#2d2d2d", fg="white", relief="flat")
add_files_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

# New button for the operation
execute_operation_button = tk.Button(root, text="Start Attack", command=start_operation_process, bg="#2d2d2d", fg="white", relief="flat")
execute_operation_button.grid(row=8, column=0, columnspan=2, padx=10, pady=10)

# Debug window toggle button
debug_button = tk.Button(root, text="Toggle Debug Window", 
                        command=lambda: debug_window.deiconify() if debug_window.state() == 'iconic' else debug_window.lift(),
                        bg="#2d2d2d", fg="white", relief="flat")
debug_button.grid(row=9, column=0, columnspan=2, padx=10, pady=10)

# Configure style for the progress bar
style = ttk.Style()
style.configure("TProgressbar", thickness=20)

# Main loop
root.mainloop()
