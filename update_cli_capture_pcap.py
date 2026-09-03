with open("blackoutkit/cli.py", "r") as f:
    code = f.read()

old_block = """        def _on_packet(pkt: dict):
            packets.append(pkt)"""

new_block = """        pcap_file = getattr(args, "pcap", None)
        raw_packets = [] if pcap_file else None

        def _on_packet(pkt: dict):
            packets.append(pkt)

        def _on_raw_packet(pkt):
            if raw_packets is not None:
                raw_packets.append(pkt)
            _on_packet(net_tools.parse_packet_summary(pkt))"""

old_run = """                net_tools.capture_packets(
                    iface=iface,
                    bpf_filter=bpf_filter,
                    count=count,
                    stop_event=stop_event,
                    on_packet=_on_packet,
                )"""

new_run = """                if pcap_file:
                    import scapy.all as scapy
                    scapy.sniff(
                        iface=iface or None,
                        filter=bpf_filter or None,
                        count=count or 0,
                        prn=_on_raw_packet,
                        stop_filter=lambda _p: stop_event.is_set(),
                        store=False,
                    )
                else:
                    net_tools.capture_packets(
                        iface=iface,
                        bpf_filter=bpf_filter,
                        count=count,
                        stop_event=stop_event,
                        on_packet=_on_packet,
                    )"""

pcap_save_block = """        if pcap_file and raw_packets:
            ok = net_tools.write_pcap_file(pcap_file, raw_packets)
            if ok:
                console.print(f"[success]✓ Exported {len(raw_packets)} captured packets to standard PCAP file: [bold]{pcap_file}[/bold][/success]")
            else:
                console.print(f"[error]Failed to write PCAP file to {pcap_file}[/error]")"""

old_end = """        summary = net_tools.summarize_capture_packets(list(packets))
        console.print(_capture_summary_table(summary))
        console.print()"""

new_end = """        summary = net_tools.summarize_capture_packets(list(packets))
        console.print(_capture_summary_table(summary))
""" + pcap_save_block + "\n        console.print()"

if old_block in code and old_run in code:
    code = code.replace(old_block, new_block)
    code = code.replace(old_run, new_run)
    code = code.replace(old_end, new_end)
    with open("blackoutkit/cli.py", "w") as f:
        f.write(code)
    print("Successfully updated capture PCAP support in blackoutkit/cli.py")
else:
    print("Could not locate capture blocks in blackoutkit/cli.py")
