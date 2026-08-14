import customtkinter as ctk
import threading
import time
import math

WORLD_MAP = [
    "         .......                                          .......                       ",
    "       ...........                                      ...........            .....    ",
    "      .............                                    .............         .........  ",
    "       .............    ...                            ..............       ........... ",
    "        ............  .....                           ................     .............",
    "         ..................                           ................     .............",
    "          .................                          ..................    .............",
    "           ................                          ..................   ..............",
    "            ...............                          ..................   ..............",
    "              ............                            .................   ............. ",
    "               ..........                             .................    ...........  ",
    "                 .......                               ...............      .........   ",
    "                   ....                                ...............        .....     ",
    "                    ...                                 .............                   ",
    "                                                         ...........                ... ",
    "                                                          .........               ......",
    "                                                            .....                .......",
    "                                                              .                   ..... ",
]

class ConnectionMapCanvas(ctk.CTkCanvas):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.is_active = False
        self.color = "#00A8FF"
        self.nodes = {
            "us": (15, 6),
            "eu": (48, 5),
            "asia": (70, 7)
        }
        self.current_target = "eu"
        self.anim_progress = 0.0
        self._anim_job = None
        self.bind("<Configure>", self.draw_map)

    def draw_map(self, event=None):
        self.delete("all")
        width = int(self.winfo_width())
        height = int(self.winfo_height())
        if width <= 1: width = 500
        if height <= 1: height = 200
        
        # Calculate cell size
        rows = len(WORLD_MAP)
        cols = len(WORLD_MAP[0])
        cell_w = width / cols
        cell_h = height / rows
        
        # Draw dotted map
        for r, row_str in enumerate(WORLD_MAP):
            for c, char in enumerate(row_str):
                if char == ".":
                    x = c * cell_w + (cell_w/2)
                    y = r * cell_h + (cell_h/2)
                    self.create_oval(x-1, y-1, x+1, y+1, fill="#333", outline="#333")
                    
        self.cell_w = cell_w
        self.cell_h = cell_h
        
        self.draw_overlay()
        
    def draw_overlay(self):
        self.delete("overlay")
        
        us_x = self.nodes["us"][0] * self.cell_w
        us_y = self.nodes["us"][1] * self.cell_h
        target_x = self.nodes[self.current_target][0] * self.cell_w
        target_y = self.nodes[self.current_target][1] * self.cell_h
        
        # Draw base nodes
        self.create_oval(us_x-4, us_y-4, us_x+4, us_y+4, fill=self.color, outline="", tags="overlay")
        
        if self.is_active:
            # Draw target node
            self.create_oval(target_x-4, target_y-4, target_x+4, target_y+4, fill=self.color, outline="", tags="overlay")
            
            # Animate line
            self.anim_progress += 0.05
            if self.anim_progress > 1.0:
                self.anim_progress = 0.0
                
            curr_x = us_x + (target_x - us_x) * self.anim_progress
            curr_y = us_y + (target_y - us_y) * self.anim_progress - (math.sin(self.anim_progress * math.pi) * 30) # Arc effect
            
            # Draw trail
            self.create_line(us_x, us_y, curr_x, curr_y, fill=self.color, width=2, tags="overlay", dash=(4, 4))
            
            # Draw pulse ring on target
            pulse_rad = 15 * (1.0 - self.anim_progress)
            self.create_oval(target_x-pulse_rad, target_y-pulse_rad, target_x+pulse_rad, target_y+pulse_rad, outline=self.color, tags="overlay")
            
            if self._anim_job:
                try:
                    self.after_cancel(self._anim_job)
                except Exception:
                    pass
            self._anim_job = self.after(50, self.draw_overlay)

    def set_state(self, active: bool, color: str, target: str = "eu"):
        self.is_active = active
        self.color = color
        self.current_target = target
        self.anim_progress = 0.0
        if self._anim_job:
            try:
                self.after_cancel(self._anim_job)
            except Exception:
                pass
            self._anim_job = None
        self.draw_overlay()

class BlackoutGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Blackout Kit — Stealth Mode")
        self.geometry("1000x700")
        self.resizable(False, False)
        
        # Handle graceful shutdown to stop all background Tkinter tasks
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
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
        
        # Animated World Map Canvas
        self.map_frame = ctk.CTkFrame(self.home_frame, fg_color="transparent")
        self.map_frame.grid(row=0, column=0, pady=(0, 10), sticky="ew")
        
        self.radar = ConnectionMapCanvas(
            self.map_frame, 
            height=180, 
            bg="#181818", 
            highlightthickness=0
        )
        self.radar.pack(fill="x", padx=10, pady=10)

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
        
        self.iran_mode_var = ctk.BooleanVar(value=False)
        self.killswitch_var = ctk.BooleanVar(value=False)
        
        self.iran_mode_switch = ctk.CTkSwitch(self.settings_frame, text="Enable TIC 2026 Evasion Profile (Iran Mode)", variable=self.iran_mode_var)
        self.iran_mode_switch.grid(row=1, column=0, pady=10, sticky="w")
        
        self.killswitch_switch = ctk.CTkSwitch(self.settings_frame, text="Network Kill Switch (Block traffic if proxy drops)", variable=self.killswitch_var)
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

        # State Machine
        self.current_state = "DISCONNECTED" # "DISCONNECTED", "CONNECTING", "SECURE"
        self.uptime_seconds = 0
        self._uptime_job = None
        self._connection_attempt = 0
        
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
        if self.current_state == "DISCONNECTED":
            self.connect()
        else:
            self.disconnect()
            
    def connect(self):
        if self.current_state != "DISCONNECTED":
            return
        self.current_state = "CONNECTING"
        self.connect_btn.configure(text="CONNECTING...", fg_color="#ff9900", hover_color="#cc7a00")
        self.status_label.configure(text="CONNECTING", text_color="#ff9900")
        self.engine_selector.configure(state="disabled")
        
        self.radar.set_state(True, "#ff9900")
        
        self.append_log(f"[*] Preparing {self.engine_var.get()} engine...")
        
        self._connection_attempt += 1
        current_attempt = self._connection_attempt
        
        # Start real connection in a background thread
        threading.Thread(target=self._real_connect, args=(current_attempt,), daemon=True).start()
        
    def _real_connect(self, attempt: int):
        from . import daemon, settings as cfg
        engine_name = self.engine_var.get()
        
        # Save Killswitch setting
        try:
            cfg.set_value("kill_switch", self.killswitch_var.get())
        except Exception:
            pass
            
        if self.iran_mode_var.get():
            self.after(0, self.append_log, "[*] Iran Mode (TIC 2026 Evasion) active -> forcing legend profile.")
            engine_name = "legend"
        
        try:
            # Ensure no orphaned daemon is running
            daemon.stop()
            pid = daemon.start(engine_name)
            if not pid:
                self.after(0, self.append_log, "[error]Failed to start background daemon.[/error]")
                self.after(0, self.disconnect)
                return
        except Exception as e:
            self.after(0, self.append_log, f"[error]Error starting engine: {e}[/error]")
            self.after(0, self.disconnect)
            return
            
        time.sleep(1.0)
        
        # Verify we didn't cancel the connection early or start a new one
        if self.current_state != "CONNECTING" or self._connection_attempt != attempt:
            return
            
        self.after(0, self.append_log, f"[+] Proxy tunnel established (PID {pid}).")
        # Update UI from thread
        self.after(0, self._set_connected_state, attempt)
        
    def _set_connected_state(self, attempt: int):
        if self.current_state != "CONNECTING" or self._connection_attempt != attempt:
            return
        self.current_state = "SECURE"
        self.connect_btn.configure(text="DISCONNECT", fg_color="#ff3366", hover_color="#cc0044")
        self.status_label.configure(text="SECURE", text_color="#00cc66")
        
        from . import settings as cfg
        from .scanner.proxy_tester import test_tcp_port
        
        engine_name = self.engine_var.get()
        if self.iran_mode_var.get():
            engine_name = "legend"
            
        proxy_info = cfg.get_engine_proxy_details(engine_name, cfg.load())
        if proxy_info:
            p_host, p_port = proxy_info
            if isinstance(p_host, str) and p_host.startswith("socks="):
                p_host = p_host.split("=", 1)[1]
            self.ip_label.configure(text=f"{p_host}:{p_port}", text_color="#00A8FF")
            lat = test_tcp_port(p_host, p_port)
            ping_str = f"{int(lat)} ms" if lat is not None else "Active"
            self.ping_label.configure(text=ping_str, text_color="#00cc66")
        else:
            self.ip_label.configure(text="Active (TUN)", text_color="#00A8FF")
            self.ping_label.configure(text="OK", text_color="#00cc66")
            
        self.uptime_label.configure(text_color="#00A8FF")
        self.radar.set_state(True, "#00cc66")
        self.append_log("[✓] You are now secure.")
        
        # Start uptime timer
        self.uptime_seconds = 0
        self._update_uptime()
        
        # Start log tailer
        threading.Thread(target=self._tail_logs, args=(attempt,), daemon=True).start()
        
    def _tail_logs(self, attempt: int):
        from . import daemon
        import os
        try:
            if not daemon.LOG_FILE.exists():
                return
            with open(daemon.LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2) # Go to end
                while self.current_state == "SECURE" and self._connection_attempt == attempt:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    
                    # Update UI
                    self.after(0, self.append_log, line.strip())
        except Exception:
            pass
        
    def _update_uptime(self):
        if self.current_state != "SECURE":
            return
        m, s = divmod(self.uptime_seconds, 60)
        h, m = divmod(m, 60)
        self.uptime_label.configure(text=f"{h:02d}:{m:02d}:{s:02d}")
        self.uptime_seconds += 1
        self._uptime_job = self.after(1000, self._update_uptime)
        
    def disconnect(self):
        if self.current_state == "DISCONNECTED":
            return
        self.current_state = "DISCONNECTED"
        if self._uptime_job:
            self.after_cancel(self._uptime_job)
            self._uptime_job = None
            
        from . import daemon
        if daemon.stop():
            self.append_log("[-] Connection closed. System proxy cleared.")
        else:
            self.append_log("[-] Disconnected.")
            
        self.connect_btn.configure(text="CONNECT", fg_color="#00A8FF", hover_color="#008ecc")
        self.status_label.configure(text="DISCONNECTED", text_color="gray40")
        self.ip_label.configure(text="Hidden", text_color="white")
        self.ping_label.configure(text="-- ms", text_color="white")
        self.uptime_label.configure(text="00:00:00", text_color="white")
        self.engine_selector.configure(state="normal")
        self.radar.set_state(False, "#00A8FF")

    def on_closing(self):
        if self.current_state != "DISCONNECTED":
            try:
                from . import daemon
                daemon.stop()
            except Exception:
                pass
        # Cancel all pending after tasks before destroying
        try:
            for after_id in self.tk.call('after', 'info'):
                self.after_cancel(after_id)
        except Exception:
            pass
        self.destroy()

def run_gui():
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    app = BlackoutGUI()
    
    # Suppress CustomTkinter background loop 'invalid command' errors after destruction
    def silent_callback_exception(exc, val, tb):
        pass
    app.report_callback_exception = silent_callback_exception
    
    app.mainloop()
    return True

if __name__ == "__main__":
    run_gui()
