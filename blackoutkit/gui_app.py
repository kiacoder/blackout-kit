import customtkinter as ctk
import threading
import time

class BlackoutGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Blackout Kit — Native App")
        self.geometry("900x600")
        self.resizable(False, False)
        
        # Configure grid layout (1x2)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Create sidebar frame
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#1a1a1a")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="BLACKOUT", font=ctk.CTkFont(size=24, weight="bold"), text_color="#00A8FF")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        self.btn_home = ctk.CTkButton(self.sidebar_frame, text="Dashboard", fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w", command=self.show_home)
        self.btn_home.grid(row=1, column=0, padx=20, pady=10)

        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="Settings", fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w", command=self.show_settings)
        self.btn_settings.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_logs = ctk.CTkButton(self.sidebar_frame, text="Live Logs", fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w", command=self.show_logs)
        self.btn_logs.grid(row=3, column=0, padx=20, pady=10)

        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Dark", "Light", "System"], command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 20))

        # --- HOME FRAME ---
        self.home_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.home_frame.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)
        self.home_frame.grid_rowconfigure(3, weight=1)
        self.home_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(self.home_frame, text="DISCONNECTED", font=ctk.CTkFont(size=36, weight="bold"), text_color="gray")
        self.status_label.grid(row=0, column=0, pady=(40, 20))
        
        self.ip_label = ctk.CTkLabel(self.home_frame, text="IP: Hidden • Ping: -- ms", font=ctk.CTkFont(size=14))
        self.ip_label.grid(row=1, column=0, pady=(0, 40))

        self.connect_btn = ctk.CTkButton(
            self.home_frame, 
            text="CONNECT", 
            font=ctk.CTkFont(size=24, weight="bold"), 
            height=80, 
            width=280, 
            corner_radius=40,
            fg_color="#00A8FF",
            hover_color="#008ecc",
            command=self.toggle_connection
        )
        self.connect_btn.grid(row=2, column=0, pady=20)
        
        # Engine selector
        from .cli import ALL_ENGINE_CHOICES
        self.engine_var = ctk.StringVar(value="auto")
        self.engine_selector = ctk.CTkOptionMenu(
            self.home_frame, 
            values=ALL_ENGINE_CHOICES, 
            variable=self.engine_var,
            width=200,
            font=ctk.CTkFont(size=14)
        )
        self.engine_selector.grid(row=3, column=0, pady=20, sticky="n")

        # --- SETTINGS FRAME ---
        self.settings_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.settings_frame.grid_rowconfigure(10, weight=1)
        self.settings_frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(self.settings_frame, text="Security & Preferences", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, pady=(0, 20), sticky="w")
        
        self.iran_mode_switch = ctk.CTkSwitch(self.settings_frame, text="Enable TIC 2026 Evasion Profile (Iran Mode)")
        self.iran_mode_switch.grid(row=1, column=0, pady=10, sticky="w")
        
        self.killswitch_switch = ctk.CTkSwitch(self.settings_frame, text="Network Kill Switch (Block traffic if proxy drops)")
        self.killswitch_switch.grid(row=2, column=0, pady=10, sticky="w")
        
        # --- LOGS FRAME ---
        self.logs_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.logs_frame.grid_rowconfigure(1, weight=1)
        self.logs_frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(self.logs_frame, text="Live Engine Logs", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, pady=(0, 10), sticky="w")
        
        self.log_textbox = ctk.CTkTextbox(self.logs_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_textbox.grid(row=1, column=0, sticky="nsew")
        self.log_textbox.insert("0.0", "--- Blackout Kit Ready ---\n")
        self.log_textbox.configure(state="disabled")

        # State
        self.is_connected = False
        
        # Default view
        self.show_home()

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def show_home(self):
        self.settings_frame.grid_forget()
        self.logs_frame.grid_forget()
        self.home_frame.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)

    def show_settings(self):
        self.home_frame.grid_forget()
        self.logs_frame.grid_forget()
        self.settings_frame.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)
        
    def show_logs(self):
        self.home_frame.grid_forget()
        self.settings_frame.grid_forget()
        self.logs_frame.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)

    def append_log(self, text):
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", text + "\n")
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def toggle_connection(self):
        if not self.is_connected:
            self.connect()
        else:
            self.disconnect()
            
    def connect(self):
        self.is_connected = True
        self.connect_btn.configure(text="CONNECTING...", fg_color="#ff9900", hover_color="#cc7a00")
        self.status_label.configure(text="CONNECTING", text_color="#ff9900")
        self.engine_selector.configure(state="disabled")
        
        self.append_log(f"[*] Preparing {self.engine_var.get()} engine...")
        
        # Simulate connection in a background thread
        threading.Thread(target=self._mock_connect, daemon=True).start()
        
    def _mock_connect(self):
        time.sleep(1.5)
        self.append_log("[+] Proxy tunnel established successfully.")
        
        # Update UI from thread (CustomTkinter is mostly thread-safe for simple configures, but ideally use after())
        self.after(0, self._set_connected_state)
        
    def _set_connected_state(self):
        self.connect_btn.configure(text="DISCONNECT", fg_color="#ff3333", hover_color="#cc0000")
        self.status_label.configure(text="SECURE", text_color="#00cc66")
        self.ip_label.configure(text="IP: 104.18.2.19 • Ping: 42 ms")
        self.append_log("[✓] You are now secure.")
        
    def disconnect(self):
        self.is_connected = False
        self.connect_btn.configure(text="CONNECT", fg_color="#00A8FF", hover_color="#008ecc")
        self.status_label.configure(text="DISCONNECTED", text_color="gray")
        self.ip_label.configure(text="IP: Hidden • Ping: -- ms")
        self.engine_selector.configure(state="normal")
        self.append_log("[-] Connection closed. System proxy cleared.")


def run_gui():
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    app = BlackoutGUI()
    
    # Suppress CustomTkinter background loop 'invalid command' errors after destruction
    def silent_callback_exception(exc, val, tb):
        pass
    app.report_callback_exception = silent_callback_exception
    
    app.mainloop()
    
    # Cancel pending after tasks
    try:
        for after_id in app.tk.call('after', 'info'):
            app.after_cancel(after_id)
    except Exception:
        pass
        
    app.destroy()
    return True

if __name__ == "__main__":
    run_gui()
