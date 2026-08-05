import sys
import subprocess
from pathlib import Path
import threading

def start_launcher():
    try:
        import customtkinter as ctk
    except ImportError:
        print("[!] customtkinter is not installed. Falling back to terminal mode.")
        print("[!] Run: pip install customtkinter")
        return False

    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    app = ctk.CTk()
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
    
    # Engine Dropdown
    ctk.CTkLabel(settings_frame, text="Engine Selection:").pack(anchor="w", pady=(10,0))
    engine_var = ctk.StringVar(value="auto")
    engine_dropdown = ctk.CTkComboBox(settings_frame, variable=engine_var, values=["auto", "sni", "gdpi", "xray", "wireguard", "psiphon", "hysteria2"])
    engine_dropdown.pack(fill="x", pady=(0,10))
    
    # Mode Dropdown
    ctk.CTkLabel(settings_frame, text="Security Mode:").pack(anchor="w")
    mode_var = ctk.StringVar(value="speed")
    mode_dropdown = ctk.CTkComboBox(settings_frame, variable=mode_var, values=["speed", "private", "legend"])
    mode_dropdown.pack(fill="x", pady=(0,10))
    
    # Killswitch
    killswitch_var = ctk.BooleanVar(value=False)
    ctk.CTkSwitch(settings_frame, text="Enable Network Killswitch", variable=killswitch_var, onvalue=True, offvalue=False).pack(anchor="w", pady=10)

    # Launch Button
    def on_launch():
        env = platform_var.get()
        use_tray = tray_var.get() == "yes"
        engine = engine_var.get()
        mode = mode_var.get()
        
        if env != "powershell":
            # Show a popup for parts still in development
            import tkinter.messagebox
            tkinter.messagebox.showinfo(
                "Coming Soon", 
                "This interface is currently In Development and will be available in a future release! Starting the standard PowerShell CLI instead."
            )
            env = "powershell"

        # We destroy the launcher window
        app.destroy()
        
        # Build the command line
        if env == "powershell":
            # For powershell, we run the CLI
            import blackoutkit.cli as cli
            import sys
            
            # Mock the arguments for cli
            sys.argv = ["blackout", "connect"]
            if engine != "auto":
                sys.argv.append(engine)
            if use_tray:
                sys.argv.append("--background")
                
            cli.main()

    launch_btn = ctk.CTkButton(app, text="LAUNCH BLACKOUT KIT 🚀", font=ctk.CTkFont(weight="bold"), height=50, command=on_launch)
    launch_btn.pack(fill="x", padx=50, pady=30)
    
    app.mainloop()
    return True
