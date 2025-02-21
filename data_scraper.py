 execute_operation(operation_type, source_path, dest_path, progress_bar, root):
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
