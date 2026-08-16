import sys
import subprocess
from pathlib import Path
import threading

def start_launcher():
    try:
        import customtkinter as ctk
    except ImportError as e:
        print(f"[!] customtkinter import failed: {e}")
        print("[!] Falling back to terminal mode.")
        print("[!] Run: pip install customtkinter")
        return False

    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    app = ctk.CTk()
    
    # Suppress CustomTkinter background loop 'invalid command' errors after destruction
    def silent_callback_exception(exc, val, tb):
        pass
    app.report_callback_exception = silent_callback_exception
    
    app.title("Blackout Kit — Universal Launcher")
    app.geometry("600x700")
    app.resizable(False, False)
    
    # Header
    header_font = ctk.CTkFont(family="Inter", size=32, weight="bold")
    header = ctk.CTkLabel(app, text="BLACKOUT KIT", font=header_font, text_color="#00A8FF")
    header.pack(pady=(30, 10))
    
    sub_header = ctk.CTkLabel(app, text="Select your workspace environment", font=ctk.CTkFont(size=14), text_color="gray")
    sub_header.pack(pady=(0, 20))
    
    # 1. Environment Selection
    env_frame = ctk.CTkFrame(app, fg_color="transparent")
    env_frame.pack(fill="x", padx=50, pady=10)
    
    ctk.CTkLabel(env_frame, text="1. Interface / Environment", font=ctk.CTkFont(weight="bold")).pack(anchor="w")
    
    platform_var = ctk.StringVar(value="powershell")
    
    opts = [
        ("Blackout Kit PowerShell (CLI)", "powershell"),
        ("Blackout Kit WSL Ubuntu (Linux) [In Development]", "wsl"),
        ("Blackout Kit Windows (Native App) [In Development]", "native"),
        ("Blackout Kit WEB App (Dashboard) [In Development]", "web")
    ]
    
    for text, val in opts:
        ctk.CTkRadioButton(env_frame, text=text, variable=platform_var, value=val).pack(anchor="w", pady=5)
        
    # 2. System Tray
    tray_frame = ctk.CTkFrame(app, fg_color="transparent")
    tray_frame.pack(fill="x", padx=50, pady=10)
    
    ctk.CTkLabel(tray_frame, text="2. Run in System Tray (Background)", font=ctk.CTkFont(weight="bold")).pack(anchor="w")
    
    tray_var = ctk.StringVar(value="no")
    ctk.CTkRadioButton(tray_frame, text="Yes, hide terminal and run in tray", variable=tray_var, value="yes").pack(anchor="w", pady=5)
    ctk.CTkRadioButton(tray_frame, text="No, run normally", variable=tray_var, value="no").pack(anchor="w", pady=5)

    # 3. Connection Settings
    settings_frame = ctk.CTkFrame(app, fg_color="transparent")
    settings_frame.pack(fill="x", padx=50, pady=10)
    
    ctk.CTkLabel(settings_frame, text="3. Connection Profile", font=ctk.CTkFont(weight="bold")).pack(anchor="w")
    
    # Mode Dropdown
    ctk.CTkLabel(settings_frame, text="Security Mode:").pack(anchor="w")
    mode_var = ctk.StringVar(value="speed")
    mode_dropdown = ctk.CTkComboBox(settings_frame, variable=mode_var, values=["speed", "private", "legend"])
    mode_dropdown.pack(fill="x", pady=(0,10))
    
    ctk.CTkLabel(
        settings_frame,
        text="Linux only: endpoint-scoped kill switch requires a validated upstream endpoint.",
        text_color="gray60",
    ).pack(anchor="w", pady=10)

    
    # We will store the launch configuration here
    launch_config = {}
    
    def on_launch():
        launch_config["env"] = platform_var.get()
        launch_config["use_tray"] = tray_var.get() == "yes"
        launch_config["mode"] = mode_var.get()
        
        if launch_config["env"] not in ["powershell", "native"]:
            # Show a popup for parts still in development (web, wsl)
            import tkinter.messagebox
            tkinter.messagebox.showinfo(
                "Coming Soon", 
                "This interface is currently In Development and will be available in a future release! Starting the standard PowerShell CLI instead."
            )
            launch_config["env"] = "powershell"

        # Schedule the exit so that the button's click animation can finish cleanly
        app.after(200, app.quit)
        
    launch_btn = ctk.CTkButton(app, text="LAUNCH BLACKOUT KIT 🚀", font=ctk.CTkFont(weight="bold"), height=50, command=on_launch)
    launch_btn.pack(fill="x", padx=50, pady=30)
    
    app.mainloop()
    
    # Cancel all pending background tasks (like CustomTkinter's update loop) to prevent Tcl errors
    try:
        for after_id in app.tk.call('after', 'info'):
            app.after_cancel(after_id)
    except Exception:
        pass
        
    # Properly destroy the window after the mainloop exits
    app.destroy()
    
    # If the user closed the window without launching, return True so the program exits normally
    if not launch_config:
        return True
        
    # Execute the selected logic
    if launch_config["env"] == "powershell":
        import blackoutkit.typer_cli as typer_cli
        typer_cli.connect(pos_engine=None, engine=None, background=launch_config["use_tray"], iran=False)
        
    elif launch_config["env"] == "native":
        import subprocess, sys, os
        cmd = [sys.executable, "gui"] if getattr(sys, 'frozen', False) else [sys.executable, sys.argv[0], "gui"]
        subprocess.Popen(cmd, creationflags=0x08000000 if os.name == 'nt' else 0) # CREATE_NO_WINDOW
        os._exit(0)
        
    return True
