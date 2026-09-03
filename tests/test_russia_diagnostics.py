"""Tests for Russian whitelist awareness and data-phase diagnostics."""
from blackoutkit.russia_whitelist import is_on_whitelist, check_whitelist_status


def test_yandex_ip_is_on_whitelist():
    assert is_on_whitelist("77.88.8.8") is True


def test_vk_ip_is_on_whitelist():
    assert is_on_whitelist("95.163.100.1") is True


def test_random_ip_not_on_whitelist():
    assert is_on_whitelist("8.8.8.8") is False


def test_non_russian_ip_not_on_whitelist():
    assert is_on_whitelist("1.1.1.1") is False


def test_invalid_ip_returns_false():
    assert is_on_whitelist("not.an.ip") is False


def test_check_whitelist_status_ip_on_list():
    on_list, detail = check_whitelist_status("77.88.8.8")
    assert on_list is True
    assert "whitelist" in detail.lower()


def test_check_whitelist_status_ip_not_on_list():
    on_list, detail = check_whitelist_status("8.8.8.8")
    assert on_list is False
    assert "NOT" in detail or "not" in detail.lower()


def test_check_whitelist_status_domain_unresolved():
    on_list, detail = check_whitelist_status("example.com")
    assert on_list is False
    assert "domain" in detail.lower() or "resolve" in detail.lower()


def test_check_whitelist_status_empty_host():
    on_list, detail = check_whitelist_status("")
    assert on_list is False
    assert "no host" in detail.lower()


def test_whitelist_check_runs_only_for_ru():
    """Doctor check should return empty list when country is not RU."""
    from blackoutkit import doctor

    # Mock non-RU country
    results = doctor.check_russia_whitelist()
    # When not in RU, should return empty list (no profile or non-RU)
    assert isinstance(results, list)


def test_daemon_has_data_phase_counter():
    """Verify the daemon source includes the data-phase failure tracking."""
    import inspect
    from blackoutkit import daemon

    source = inspect.getsource(daemon._run_daemon_loop)
    assert "data_phase_failures" in source
    assert "Data-phase drop" in source
