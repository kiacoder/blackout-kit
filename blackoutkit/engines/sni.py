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
        
        if dll.StartSNIC(c_path) == 0:
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



    def _run_auto_scan(self, dll, c_path) -> str | None:
        import asyncio
        import time
        from ..scanner import ip_scanner
        from rich.table import Table
        from ..theme import console
        
        console.print("[cyan]Auto-detecting best Cloudflare IP for SNI spoofing...[/cyan]")
        
        scan_ip_count = cfg.get("scan_ip_count", 100)
        scan_concurrency = cfg.get("scan_concurrency", 100)
        scan_timeout = cfg.get("scan_timeout", 2.0)
        
        from ..scanner.ip_scanner import KNOWN_GOOD_IPS
        loop = asyncio.new_event_loop()
        cf_results = []
        try:
            # Phase 1: Extremely fast scan of known good IPs
            console.print("[dim]Phase 1: Quick-checking known good IPs...[/dim]")
            cf_results = loop.run_until_complete(ip_scanner.scan_ips(
                KNOWN_GOOD_IPS, concurrency=len(KNOWN_GOOD_IPS), timeout=1.0
            ))
            
            if cf_results and cf_results[0][1] < 150.0:
                console.print(f"[green]Found fast known IP: {cf_results[0][0]} ({cf_results[0][1]:.1f}ms)[/green]")
            else:
                # Phase 2: Full scan if no excellent known IPs are found
                ips = ip_scanner.generate_cloudflare_ips(scan_ip_count)
                console.print(f"[dim]Phase 2: Scanning {scan_ip_count} Cloudflare IPs...[/dim]")
                more_results = loop.run_until_complete(ip_scanner.scan_ips(
                    ips, concurrency=scan_concurrency, timeout=scan_timeout
                ))
                cf_results.extend(more_results)
                cf_results.sort(key=lambda x: x[1])
        finally:
            loop.close()
            
        if not cf_results:
            self._log.error("No reachable Cloudflare IPs found. Check your internet connection.")
            return None
            
        always_test_all = cfg.get("sni_always_test_all_ips")
        custom_ips = cfg.get("sni_custom_ips") or []
        if always_test_all:
            reachable_ips = [ip for ip, _ in cf_results]
            # Combine custom IPs with all reachable IPs, preserving order and removing duplicates
            top_candidates = list(dict.fromkeys(custom_ips + reachable_ips))
            self._log.info("Testing ALL reachable candidates (including custom): %d IPs", len(top_candidates))
        else:
            # Test custom IPs plus top 5 reachable candidates
            reachable_top = [ip for ip, _ in cf_results[:5]]
            top_candidates = list(dict.fromkeys(custom_ips + reachable_top))
            
            # Fast-path cache: if current connect IP is still good, prioritize it
            current_ip = cfg.get("sni_connect_ip")
            if current_ip and current_ip not in top_candidates:
                top_candidates.insert(0, current_ip)
                
            self._log.info("Top candidates to test (including custom/cached): %s", top_candidates)
        
        # Combine default test hosts with any user‑provided custom fake SNI hostnames
        custom_fakes = cfg.get("sni_custom_fakes") or []
        test_hosts = [
            "www.youtube.com",
            "www.google.com",
            "gemini.google.com",
            "www.microsoft.com",
            "www.discord.com",
        ] + custom_fakes
        
        scan_report = {}
        
        for ip in top_candidates:
            self._log.info("Testing candidate IP: %s", ip)
            self.connect_ip = ip
            config_path = self._write_config()
            
            # Start SNI Spoofer temporarily
            c_path_bytes = str(config_path).encode("utf-8")
            started = (dll.StartSNIC(c_path_bytes) == 0)
                
            if not started:
                self._log.warning("Could not start SNI Spoofer for candidate %s", ip)
                continue
                
            time.sleep(0.5)  # Wait for spoofer to bind
            
            import concurrent.futures
            ip_report = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(test_hosts)) as executor:
                future_to_host = {executor.submit(self._test_http_get, host): host for host in test_hosts}
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        latency = future.result()
                    except Exception:
                        latency = None
                    ip_report[host] = latency
                    if latency:
                        self._log.debug("  • %s: %dms", host, latency)
                    else:
                        self._log.debug("  • %s: FAILED", host)
                    
            scan_report[ip] = ip_report
            
            # Stop SNI Spoofer
            dll.StopSNIC()
            time.sleep(0.2)
            
            # Fast-path abort: if this IP succeeded all tests quickly, just use it
            success_count = sum(1 for lat in ip_report.values() if lat is not None)
            if success_count == len(test_hosts) and not always_test_all:
                avg_lat = sum(lat for lat in ip_report.values() if lat is not None) / success_count
                if avg_lat < 1500: # Decent latency
                    self._log.info("Fast-path: IP %s passed all tests quickly! Skipping remaining.", ip)
                    break
            
        # Print results table
        table = Table(title="[bold]SNI Auto-Scan Results (HTTP GET Speed Test)[/bold]", border_style="dim")
        table.add_column("Cloudflare IP", style="cyan")
        for host in test_hosts:
            parts = host.split(".")
            if "www" in host and len(parts) > 1:
                name = parts[1]
            elif len(parts) > 0:
                name = parts[0]
            else:
                name = host
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

    def _test_http_get(self, target_host: str) -> float | None:
        import socket
        import ssl
        import time
        sock = None
        try:
            start = time.monotonic()
            sock = socket.create_connection(self._health_check_addr, timeout=3.0)
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                tls12 = getattr(ssl.TLSVersion, "TLS1_2", None)
                if tls12 is None:
                    tls12 = getattr(ssl.TLSVersion, "TLSv1_2")
                context.minimum_version = tls12
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                # codeql[py/insecure-protocol-defaults]
                with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                    req = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
                    ssock.sendall(req.encode())
                    resp = ssock.recv(4096)
                    latency = (time.monotonic() - start) * 1000
                    if b"HTTP/" in resp:
                        return latency
                    return None
            except Exception:
                return None
        except Exception:
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
