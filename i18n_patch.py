with open("blackoutkit/theme.py", "r") as f:
    code = f.read()

i18n_code = '''

# ─────────────────────────── i18n Dictionary ───────────────────

I18N_STRINGS = {
    "en": {
        "welcome": "Welcome to Blackout Kit",
        "connected": "System Secured",
        "disconnected": "Disconnected"
    },
    "fa": {
        "welcome": "به بلک‌آوت کیت خوش آمدید",
        "connected": "سیستم امن شد",
        "disconnected": "قطع شد"
    },
    "ru": {
        "welcome": "Добро пожаловать в Blackout Kit",
        "connected": "Система защищена",
        "disconnected": "Отключено"
    }
}

def get_i18n_string(key: str, lang: str = "en") -> str:
    """Return localized string for key and language."""
    return I18N_STRINGS.get(lang, I18N_STRINGS["en"]).get(key, key)
'''

if "I18N_STRINGS" not in code:
    code += i18n_code
    with open("blackoutkit/theme.py", "w") as f:
        f.write(code)
    print("Added i18n support to blackoutkit/theme.py")
