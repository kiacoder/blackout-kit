with open("blackoutkit/tools.py", "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "return f\"Download:" in line:
        lines[i] = "    return f\"Download: {rx_mbps:6.2f} Mbps [{rx_bar:<{bar_width}}]\\nUpload:   {tx_mbps:6.2f} Mbps [{tx_bar:<{bar_width}}]\"\n"
        if i + 1 < len(lines) and "Upload:" in lines[i+1]:
            lines[i+1] = ""

with open("blackoutkit/tools.py", "w") as f:
    f.writelines(lines)
print("Fixed blackoutkit/tools.py string literal")
