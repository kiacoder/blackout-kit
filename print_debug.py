import sys
import blackoutkit.daemon as daemon
import blackoutkit.daemon.ownership as ownership
import json
from pathlib import Path

def test_stop():
    tmp_path = Path("C:/Users/kiacoder/AppData/Local/Temp/pytest-debug-tmp")
    tmp_path.mkdir(exist_ok=True, parents=True)
    lease_file = tmp_path / "daemon.lease.json"
    lease_file.write_text(json.dumps({
        "schema_version": 1,
        "pid": 4242,
        "generation": "gen-1",
        "create_time": 10.0,
    }), encoding="utf-8")
    
    daemon.APP_DATA_DIR = tmp_path
    daemon.LEASE_FILE = lease_file
    daemon._lease_path = lambda: lease_file
    daemon.get_pid = lambda: 4242
    ownership.process_identity_state = lambda *a, **k: True
    ownership.process_is_gone = lambda *a, **k: True
    daemon.time.sleep = lambda *a, **k: None
    daemon._clear_owned_metadata = lambda *a, **k: True
    daemon._active_lease = lambda pid=None: {"pid": 4242, "generation": "gen-1", "create_time": 10.0}

    def still_owned() -> bool:
        matches = daemon.lease_matches(daemon._lease_path(), "gen-1", 4242)
        state = daemon.process_identity_state(4242, 10.0)
        print("STILL_OWNED:", matches, state)
        return matches and state is True

    still_owned()
    
test_stop()
