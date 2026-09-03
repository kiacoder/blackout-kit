with open("tests/test_ten_mega_features.py", "r") as f:
    code = f.read()

code = code.replace("from blackoutkit.daemon import is_running", "from blackoutkit import daemon")
code = code.replace("assert is_running() in (True, False)", "assert daemon.is_running() in (True, False)")

with open("tests/test_ten_mega_features.py", "w") as f:
    f.write(code)

print("Updated test_ten_mega_features import")
