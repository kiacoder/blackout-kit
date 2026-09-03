with open("blackoutkit/gui_app.py", "r") as f:
    code = f.read()

# Add Cyber Tools Tab
gui_tools_tab = '''
        self.btn_tools = ctk.CTkButton(self.sidebar_frame, text="🛡️ Cyber Tools", font=btn_font, fg_color="transparent", text_color="gray80", hover_color="#202020", anchor="w", height=40, command=self.show_tools)
        self.btn_tools.grid(row=4, column=0, padx=20, pady=5, sticky="ew")
'''

gui_tools_frame = '''
        # --- CYBER TOOLS FRAME ---
        self.tools_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.tools_frame.grid_rowconfigure(2, weight=1)
        self.tools_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.tools_frame, text="🛡️ Cyber Security & Diagnostics Suite", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, pady=(0, 15), sticky="w")

        tools_btn_frame = ctk.CTkFrame(self.tools_frame, fg_color="transparent")
        tools_btn_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkButton(tools_btn_frame, text="🚨 Panic Button", fg_color="#ef4444", hover_color="#dc2626", font=ctk.CTkFont(weight="bold"), command=self.run_gui_panic).pack(side="left", padx=5)
        ctk.CTkButton(tools_btn_frame, text="🛡️ Audit System", fg_color="#3b82f6", hover_color="#2563eb", font=ctk.CTkFont(weight="bold"), command=self.run_gui_audit).pack(side="left", padx=5)
        ctk.CTkButton(tools_btn_frame, text="👁️ Process Monitor", fg_color="#10b981", hover_color="#059669", font=ctk.CTkFont(weight="bold"), command=self.run_gui_proc_mon).pack(side="left", padx=5)
        ctk.CTkButton(tools_btn_frame, text="🤖 AI Explainer", fg_color="#8b5cf6", hover_color="#7c3aed", font=ctk.CTkFont(weight="bold"), command=self.run_gui_ai_explain).pack(side="left", padx=5)

        self.tools_output = ctk.CTkTextbox(self.tools_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.tools_output.grid(row=2, column=0, sticky="nsew")
        self.tools_output.insert("0.0", "--- Select a Cyber Tool above ---\\n")
        self.tools_output.configure(state="disabled")
'''

gui_tools_methods = '''
    def show_tools(self):
        self.home_frame.grid_forget()
        self.settings_frame.grid_forget()
        self.logs_frame.grid_forget()
        self.tools_frame.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)

    def print_tool_output(self, text):
        self.tools_output.configure(state="normal")
        self.tools_output.delete("0.0", "end")
        self.tools_output.insert("0.0", text)
        self.tools_output.configure(state="disabled")

    def run_gui_panic(self):
        from .tools import trigger_panic
        res = trigger_panic()
        out = "🚨 EMERGENCY PANIC ACTIVATED 🚨\\n\\n" + "\\n".join(f"• {r['step']}: {'✓ OK' if r['ok'] else '✗ Failed'} ({r['detail']})" for r in res)
        self.print_tool_output(out)

    def run_gui_audit(self):
        from .tools import run_network_audit
        res = run_network_audit()
        out = f"🛡️ NETWORK HARDENING AUDIT (Score: {res['score']}/100 Grade: {res['grade']})\\n\\n" + "\\n".join(f"• [{f['severity']}] {f['category']}: {f['summary']} -> {f['recommendation']}" for f in res['findings'])
        self.print_tool_output(out)

    def run_gui_proc_mon(self):
        from .tools import monitor_process_network
        procs = monitor_process_network()
        out = "👁️ PROCESS NETWORK MONITOR (Top Talkers)\\n\\n" + "\\n".join(f"• PID {p['pid']} [{p['process']}]: {p['socket_count']} sockets ({p['protocols']}) Remote: {p['remote_sample']}" for p in procs[:20])
        self.print_tool_output(out)

    def run_gui_ai_explain(self):
        from .tools import explain_network_state
        res = explain_network_state()
        out = f"🤖 AI NETWORK EXPLAINER\\n\\nSecurity Score: {res['security_score']}/100 ({res['grade']})\\nActive Processes: {res['active_processes_count']}\\n\\nAnomalies:\\n" + "\\n".join(f"• {a}" for a in res['anomalies'])
        self.print_tool_output(out)
'''

if "def show_tools(self):" not in code:
    code = code.replace('self.btn_logs.grid(row=3, column=0, padx=20, pady=5, sticky="ew")', 'self.btn_logs.grid(row=3, column=0, padx=20, pady=5, sticky="ew")\n' + gui_tools_tab)
    code = code.replace('# --- LOGS FRAME ---', gui_tools_frame + '\n        # --- LOGS FRAME ---')
    code = code.replace('def show_logs(self):', gui_tools_methods + '\n    def show_logs(self):')
    with open("blackoutkit/gui_app.py", "w") as f:
        f.write(code)
    print("Successfully added Cyber Tools tab to GUI in blackoutkit/gui_app.py")
