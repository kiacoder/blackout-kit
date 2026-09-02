from pathlib import Path

from blackoutkit import resource_path


def test_bundled_resources_are_available_from_source_tree():
    for relative in (
        "data/cloudflare_ips.txt",
        "data/fake_snis.txt",
        "data/gas_ids.txt",
        "assets/world_map.jpg",
    ):
        path = resource_path(relative)
        assert isinstance(path, Path)
        assert path.is_file()
