"""
Blackout Kit - SNI Spoofing engine.
Wraps patterniha's SNI-Spoofing binary.
Injects a fake TLS ClientHello to fool DPI,
while relaying the real connection to a Cloudflare IP.

Rare upgrades:
  - Logs config params (connect_ip, fake_sni, listen_port) on start
  - wait_for_port() confirms the listener is accepting connections before returning True
  - Crash-check if the port never opens (process may have exited with an error)
"""
import json
import subprocess
from pathlib import Path
from .base import Engine
from .. import settings as cfg

SNI_BIN_NAMES = [
    "sni-spoofing.exe",
    "SNI-Spoofing_by_patterniha_v1.exe",
    "sni-spoof.exe",
    "sni.exe",
]

_STARTUP_TIMEOUT = 10.0   # seconds to wait for port to open


class SilenceOS:
    """Temporarily silence stdout and stderr at the OS level (captures C-level printf)."""
    def __enter__(self):
        import os
        try:
            self.null_fd = os.open(os.devnull, os.O_RDWR)
            self.old_stdout = os.dup(1)
            self.old_stderr = os.dup(2)
            os.dup2(self.null_fd, 1)
            os.dup2(self.null_fd, 2)
            self.success = True
        except Exception:
            self.success = False

    def __exit__(self, *_):
        import os
        if getattr(self, "success", False):
            try:
                os.dup2(self.old_stdout, 1)
                os.dup2(self.old_stderr, 2)
                os.close(self.old_stdout)
                os.close(self.old_stderr)
                os.close(self.null_fd)
            except Exception:
                pass


class SNIEngine(Engine):
    name = "sni"
    description = "SNI packet injection (patterniha method) — most effective against DPI"

    def __init__(self,
                 connect_ip: str | None = None,
                 fake_sni: str | None = None,
                 listen_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.connect_ip  = connect_ip  or s["sni_connect_ip"]
        self.fake_sni    = fake_sni    or s["sni_fake_sni"]
        self.listen_port = listen_port or s["sni_listen_port"]
        self._health_check_addr = ("127.0.0.1", self.listen_port)

    def _write_config(self) -> Path:
        config = {
            "LISTEN_HOST":  "0.0.0.0",
            "LISTEN_PORT":  self.listen_port,
            "CONNECT_IP":   self.connect_ip,
            "CONNECT_PORT": 443,
            "FAKE_SNI":     self.fake_sni,
        }
        path = self._config_dir / "config.json"
        path.write_text(json.dumps(config, indent=2))
        return path

    def start(self) -> bool:
        self._log.info(
            "Starting SNI spoofer  connect_ip=%s  fake_sni=%s  listen_port=%d",
            self.connect_ip, self.fake_sni, self.listen_port,
        )

        config_path = self._write_config()
        self._log.debug("Config written to %s", config_path)

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll is built.")
            return False

        if self.connect_ip == "auto":
            winner = self._run_auto_scan(dll, config_path)
            if not winner:
                self._log.error("Failed to auto-detect any working Cloudflare IP.")
                return False
            self.connect_ip = winner
            # Save it to settings so we keep using it until it fails or they reset it
            cfg.set_value("sni_connect_ip", winner)
            self._log.info("Selected best IP: %s (saved to settings)", winner)
            # Re-write config with the winning IP
            config_path = self._write_config()

        self._log.info("Launching SNI spoofer via native DLL")
        c_path = str(config_path).encode("utf-8")
        
        # Start the final production instance silently
        with SilenceOS():
            started = (dll.StartSNIC(c_path) == 0)
            
        if started:
            self._dll_stop_func = dll.StopSNIC
            if not self.wait_for_port(self.listen_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("SNI spoofer started via DLL but port %d never opened.", self.listen_port)
                self.stop()
                return False
            self._log.info("SNI spoofer ready natively on port %d.", self.listen_port)
            return True
        else:
            self._log.error("Native DLL StartSNIC failed")
            return False

    def stop(self):
        if hasattr(self, "_dll_stop_func") and self._dll_stop_func:
            with SilenceOS():
                try:
                    self._dll_stop_func()
                except Exception:
                    pass
            self._dll_stop_func = None
        super().stop()

    def _run_auto_scan(self, dll, c_path) -> str | None:
        import asyncio
        import time
        from ..scanner import ip_scanner
        from rich.table import Table
        from ..theme import console
        
        console.print("[cyan]Auto-detecting best Cloudflare IP for SNI spoofing...[/cyan]")
        
        # Generate and scan 30 IPs (concurrency=15, timeout=2.0)
        ips = ip_scanner.generate_cloudflare_ips(30)
        console.print("[dim]Scanning 30 Cloudflare IPs for basic TCP reachability...[/dim]")
        
        loop = asyncio.new_event_loop()
        try:
            cf_results = loop.run_until_complete(ip_scanner.scan_ips(ips, concurrency=15, timeout=2.0))
        finally:
            loop.close()
            
        if not cf_results:
            self._log.error("No reachable Cloudflare IPs found. Check your internet connection.")
            return None
            
        top_candidates = [ip for ip, latency in cf_results[:5]]
        self._log.info("Top candidates to test: %s", top_candidates)
        
        test_hosts = [
            "www.youtube.com",
            "www.google.com",
            "gemini.google.com",
            "www.microsoft.com",
            "www.discord.com"
        ]
        
        scan_report = {}
        
        for ip in top_candidates:
            self._log.info("Testing candidate IP: %s", ip)
            self.connect_ip = ip
            config_path = self._write_config()
            
            # Start SNI Spoofer temporarily
            c_path_bytes = str(config_path).encode("utf-8")
            with SilenceOS():
                started = (dll.StartSNIC(c_path_bytes) == 0)
                
            if not started:
                self._log.warning("Could not start SNI Spoofer for candidate %s", ip)
                continue
                
            time.sleep(0.5)  # Wait for spoofer to bind
            
            ip_report = {}
            for host in test_hosts:
                latency = self._test_tls_handshake(host)
                ip_report[host] = latency
                if latency:
                    self._log.debug("  • %s: %dms", host, latency)
                else:
                    self._log.debug("  • %s: FAILED", host)
                    
            scan_report[ip] = ip_report
            
            # Stop SNI Spoofer
            with SilenceOS():
                dll.StopSNIC()
            time.sleep(0.2)
            
        # Print results table
        table = Table(title="[bold]SNI Auto-Scan Results (Direct TLS Handshake)[/bold]", border_style="dim")
        table.add_column("Cloudflare IP", style="cyan")
        for host in test_hosts:
            name = host.split(".")[1] if "www" in host else host.split(".")[0]
            table.add_column(name.capitalize(), justify="right")
        table.add_column("Score", justify="right", style="bold green")
        
        winner_ip = None
        best_score = -1
        best_avg_latency = float("inf")
        
        for ip, reports in scan_report.items():
            row = [ip]
            success_count = 0
            total_latency = 0.0
            
            for host in test_hosts:
                lat = reports[host]
                if lat is not None:
                    row.append(f"{lat:.0f}ms")
                    success_count += 1
                    total_latency += lat
                else:
                    row.append("[red]✗[/red]")
            
            avg_lat = total_latency / success_count if success_count > 0 else float("inf")
            score = f"{success_count}/{len(test_hosts)}"
            row.append(score)
            table.add_row(*row)
            
            if success_count > 0:
                if (success_count > best_score) or (success_count == best_score and avg_lat < best_avg_latency):
                    best_score = success_count
                    best_avg_latency = avg_lat
                    winner_ip = ip
                    
        console.print()
        console.print(table)
        console.print()
        
        return winner_ip

    def _test_tls_handshake(self, target_host: str) -> float | None:
        import socket
        import ssl
        import time
        try:
            start = time.monotonic()
            sock = socket.create_connection(self._health_check_addr, timeout=3.0)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                latency = (time.monotonic() - start) * 1000
                return latency
        except Exception:
            return None
