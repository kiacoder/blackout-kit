import customtkinter as ctk
import threading
import time
import sys
import os
from PIL import Image

def get_asset_path(filename):
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, "assets", filename)

class BlackoutGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Blackout Kit — Stealth Mode")
        self.geometry("1000x700")
        self.resizable(False, False)
        
        # Configure grid layout (1x2)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ─── SIDEBAR FRAME ───
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#121212")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        # Brand Logo
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="BLACKOUT", 
            font=ctk.CTkFont(family="Inter", size=28, weight="bold"), 
            text_color="#00A8FF"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(40, 40))

        # Navigation Buttons
        btn_font = ctk.CTkFont(family="Inter", size=14, weight="bold")
        
        self.btn_home = ctk.CTkButton(self.sidebar_frame, text="🏠 Dashboard", font=btn_font, fg_color="transparent", text_color="gray80", hover_color="#202020", anchor="w", height=40, command=self.show_home)
        self.btn_home.grid(row=1, column=0, padx=20, pady=5, sticky="ew")

        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="⚙️ Settings", font=btn_font, fg_color="transparent", text_color="gray80", hover_color="#202020", anchor="w", height=40, command=self.show_settings)
        self.btn_settings.grid(row=2, column=0, padx=20, pady=5, sticky="ew")
        
        self.btn_logs = ctk.CTkButton(self.sidebar_frame, text="📡 Live Logs", font=btn_font, fg_color="transparent", text_color="gray80", hover_color="#202020", anchor="w", height=40, command=self.show_logs)
        self.btn_logs.grid(row=3, column=0, padx=20, pady=5, sticky="ew")

        # Theme toggle at bottom
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Theme:", font=ctk.CTkFont(family="Inter", size=12), anchor="w", text_color="gray60")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(
            self.sidebar_frame, 
            values=["Dark", "Light", "System"],
            font=ctk.CTkFont(family="Inter", size=12),
            fg_color="#1f1f1f",
            button_color="#2a2a2a",
            button_hover_color="#333333",
            command=self.change_appearance_mode_event
        )
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(5, 30), sticky="ew")

        # ─── HOME FRAME ───
        self.home_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.home_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.home_frame.grid_rowconfigure((0, 4), weight=1)
        self.home_frame.grid_columnconfigure(0, weight=1)
        
        # Map Image Background (Or Top Header)
        self.map_frame = ctk.CTkFrame(self.home_frame, fg_color="transparent")
        self.map_frame.grid(row=0, column=0, pady=(0, 20))
        
        try:
            map_image = ctk.CTkImage(
                light_image=Image.open(get_asset_path("world_map.jpg")),
                dark_image=Image.open(get_asset_path("world_map.jpg")),
                size=(350, 200)
            )
            self.map_label = ctk.CTkLabel(self.map_frame, text="", image=map_image)
            self.map_label.pack()
        except Exception:
            self.map_label = ctk.CTkLabel(self.map_frame, text="[ MAP ASSET MISSING ]", text_color="gray")
            self.map_label.pack()

        # Status Header
        self.status_label = ctk.CTkLabel(
            self.home_frame, 
            text="DISCONNECTED", 
            font=ctk.CTkFont(family="Inter", size=48, weight="bold"), 
            text_color="gray40"
        )
        self.status_label.grid(row=1, column=0, pady=(0, 20))
        
        # Info Cards Grid (3 columns now)
        self.cards_frame = ctk.CTkFrame(self.home_frame, fg_color="transparent")
        self.cards_frame.grid(row=2, column=0, pady=(0, 30))
        
        # Card 1: IP
        self.ip_card = ctk.CTkFrame(self.cards_frame, fg_color="#181818", corner_radius=15, width=140, height=70)
        self.ip_card.grid(row=0, column=0, padx=8)
        self.ip_card.grid_propagate(False)
        ctk.CTkLabel(self.ip_card, text="IP ADDRESS", font=ctk.CTkFont(size=10, weight="bold"), text_color="gray50").place(relx=0.5, rely=0.3, anchor="center")
        self.ip_label = ctk.CTkLabel(self.ip_card, text="Hidden", font=ctk.CTkFont(size=14, weight="bold"), text_color="white")
        self.ip_label.place(relx=0.5, rely=0.65, anchor="center")

        # Card 2: Ping
        self.ping_card = ctk.CTkFrame(self.cards_frame, fg_color="#181818", corner_radius=15, width=140, height=70)
        self.ping_card.grid(row=0, column=1, padx=8)
        self.ping_card.grid_propagate(False)
        ctk.CTkLabel(self.ping_card, text="PING", font=ctk.CTkFont(size=10, weight="bold"), text_color="gray50").place(relx=0.5, rely=0.3, anchor="center")
        self.ping_label = ctk.CTkLabel(self.ping_card, text="-- ms", font=ctk.CTkFont(size=14, weight="bold"), text_color="white")
        self.ping_label.place(relx=0.5, rely=0.65, anchor="center")

        # Card 3: Uptime
        self.uptime_card = ctk.CTkFrame(self.cards_frame, fg_color="#181818", corner_radius=15, width=140, height=70)
        self.uptime_card.grid(row=0, column=2, padx=8)
        self.uptime_card.grid_propagate(False)
        ctk.CTkLabel(self.uptime_card, text="UPTIME", font=ctk.CTkFont(size=10, weight="bold"), text_color="gray50").place(relx=0.5, rely=0.3, anchor="center")
        self.uptime_label = ctk.CTkLabel(self.uptime_card, text="00:00:00", font=ctk.CTkFont(size=14, weight="bold"), text_color="white")
        self.uptime_label.place(relx=0.5, rely=0.65, anchor="center")

        # Connect Button Wrapper (for glow effect)
        self.btn_wrapper = ctk.CTkFrame(self.home_frame, fg_color="transparent")
        self.btn_wrapper.grid(row=3, column=0, pady=(0, 20))

        self.connect_btn = ctk.CTkButton(
            self.btn_wrapper, 
            text="CONNECT", 
            font=ctk.CTkFont(family="Inter", size=26, weight="bold"), 
            height=90, 
            width=320, 
            corner_radius=45,
            fg_color="#00A8FF",
            hover_color="#008ecc",
            text_color="white",
            command=self.toggle_connection
        )
        self.connect_btn.pack()
        
        # Engine selector
        from .cli import ALL_ENGINE_CHOICES
        self.engine_var = ctk.StringVar(value="auto")
        
        selector_frame = ctk.CTkFrame(self.home_frame, fg_color="transparent")
        selector_frame.grid(row=4, column=0, sticky="n")
        
        ctk.CTkLabel(selector_frame, text="Active Engine:", font=ctk.CTkFont(size=13), text_color="gray50").pack(side="left", padx=(0, 10))
        self.engine_selector = ctk.CTkOptionMenu(
            selector_frame, 
            values=ALL_ENGINE_CHOICES, 
            variable=self.engine_var,
            width=160,
            fg_color="#1f1f1f",
            button_color="#2a2a2a",
            button_hover_color="#333333",
            font=ctk.CTkFont(family="Inter", size=13, weight="bold")
        )
        self.engine_selector.pack(side="left")

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
        self.connect_btn.configure(text="DISCONNECT", fg_color="#ff3366", hover_color="#cc0044")
        self.status_label.configure(text="SECURE", text_color="#00cc66")
        self.ip_label.configure(text="104.18.2.19", text_color="#00A8FF")
        self.ping_label.configure(text="42 ms", text_color="#00cc66")
        self.append_log("[✓] You are now secure.")
        
    def disconnect(self):
        self.is_connected = False
        self.connect_btn.configure(text="CONNECT", fg_color="#00A8FF", hover_color="#008ecc")
        self.status_label.configure(text="DISCONNECTED", text_color="gray40")
        self.ip_label.configure(text="Hidden", text_color="white")
        self.ping_label.configure(text="-- ms", text_color="white")
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
