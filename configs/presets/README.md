# Regional Preset Configurations

This directory contains production-ready preset configurations tailored for specific regional network environments with heavy DPI or censorship:

- `ru.yaml`: Optimized for Russian network environment (Yandex DoH, SNI fragmentation, Reality transport).
- `ir.yaml`: Optimized for Iranian network environment (Cloudflare DoH, VMess over WebSocket, TLS spoofing).
- `cn.yaml`: Optimized for Chinese network environment (Quad9 DoH, Hysteria2 / UDP obfuscation).

## Usage Examples

Run blackout kit using a regional preset:

```bash
blackout --config configs/presets/ru.yaml setup
blackout --config configs/presets/ir.yaml connect
```
