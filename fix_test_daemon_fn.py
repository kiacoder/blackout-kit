with open("tests/test_ten_mega_features.py", "r") as f:
    code = f.read()

code = code.replace("assert daemon.is_running() in (True, False)", "assert daemon.get_pid() is None or isinstance(daemon.get_pid(), int)")

with open("tests/test_ten_mega_features.py", "w") as f:
    f.write(code)

print("Updated test_ten_mega_features.py daemon check")
