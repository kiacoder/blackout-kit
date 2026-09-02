from unittest.mock import Mock

import pytest

from blackoutkit.terminal_menu import Key, MenuItem, run_menu


def _keys(*keys):
    return iter(keys).__next__


def _items():
    return [
        MenuItem("a", "Alpha", "first"),
        MenuItem("b", "Beta", "second"),
        MenuItem("c", "Gamma", "third"),
    ]


def test_space_activates_the_initially_selected_item():
    assert run_menu("Title", _items(), key_source=_keys(Key.SPACE)) == "a"


def test_enter_activates_the_initially_selected_item():
    assert run_menu("Title", _items(), key_source=_keys(Key.ENTER)) == "a"


def test_down_then_space_activates_the_next_item():
    assert run_menu("Title", _items(), key_source=_keys(Key.DOWN, Key.SPACE)) == "b"


def test_down_wraps_around_to_the_first_item():
    assert run_menu("Title", _items(), key_source=_keys(Key.DOWN, Key.DOWN, Key.DOWN, Key.SPACE)) == "a"


def test_up_wraps_around_to_the_last_item():
    assert run_menu("Title", _items(), key_source=_keys(Key.UP, Key.SPACE)) == "c"


def test_right_also_activates_the_selected_item():
    assert run_menu("Title", _items(), key_source=_keys(Key.DOWN, Key.RIGHT)) == "b"


def test_left_returns_none_for_back():
    assert run_menu("Title", _items(), key_source=_keys(Key.LEFT)) is None


def test_escape_returns_none_for_back():
    assert run_menu("Title", _items(), key_source=_keys(Key.ESCAPE)) is None


def test_ctrl_c_raises_keyboard_interrupt():
    with pytest.raises(KeyboardInterrupt):
        run_menu("Title", _items(), key_source=_keys(Key.CTRL_C))


def test_exhausted_key_source_is_treated_as_back():
    assert run_menu("Title", _items(), key_source=_keys()) is None


def test_navigation_skips_disabled_items():
    items = [
        MenuItem("a", "Alpha"),
        MenuItem("b", "Beta", enabled=False),
        MenuItem("c", "Gamma"),
    ]
    assert run_menu("Title", items, key_source=_keys(Key.DOWN, Key.SPACE)) == "c"


def test_no_enabled_items_returns_none_without_reading_keys():
    items = [MenuItem("a", "Alpha", enabled=False)]
    assert run_menu("Title", items, key_source=_keys()) is None


def test_selection_starts_on_first_enabled_item():
    items = [
        MenuItem("a", "Alpha", enabled=False),
        MenuItem("b", "Beta"),
    ]
    assert run_menu("Title", items, key_source=_keys(Key.SPACE)) == "b"


def test_live_menu_refreshes_while_waiting_for_resize(monkeypatch):
    from unittest.mock import Mock

    live = Mock()
    live.__enter__ = Mock(return_value=live)
    live.__exit__ = Mock(return_value=False)
    live.update = Mock()
    live_class = Mock(return_value=live)
    monkeypatch.setattr("blackoutkit.terminal_menu.Live", live_class)

    assert run_menu("Title", _items(), key_source=_keys(Key.SPACE)) == "a"
    assert live_class.call_args.kwargs["screen"] is True
    assert live_class.call_args.kwargs["auto_refresh"] is True


def test_viewport_keeps_selection_visible():
    items = [MenuItem(str(i), f"Item {i}") for i in range(10)]

    from blackoutkit import terminal_menu
    panel = terminal_menu._build_panel("Title", items, 9, "guide", max_visible=3)

    with terminal_menu.console.capture() as capture:
        terminal_menu.console.print(panel)
    rendered = capture.get()
    assert "Item 9" in rendered
    assert "more above" in rendered
    assert "Item 0" not in rendered


def test_other_input_does_not_move_or_activate():
    assert run_menu(
        "Title",
        _items(),
        key_source=_keys(Key.OTHER, Key.SPACE),
    ) == "a"


def test_mouse_like_input_is_not_a_navigation_key():
    assert run_menu(
        "Title",
        _items(),
        key_source=_keys(Key.OTHER, Key.OTHER, Key.SPACE),
    ) == "a"


def test_backspace_is_available_for_text_editors():
    assert Key.BACKSPACE.name == "BACKSPACE"


def test_noninteractive_menu_does_not_read_terminal(monkeypatch):
    from blackoutkit import terminal_menu

    monkeypatch.setattr(terminal_menu, "is_interactive", lambda: False)
    read_key = Mock(side_effect=AssertionError("terminal was read"))

    assert run_menu("Title", _items(), key_source=None) is None
    read_key.assert_not_called()


def test_printable_input_filters_by_label_and_activates_match():
    assert run_menu(
        "Title",
        _items(),
        key_source=_keys("g", Key.ENTER),
    ) == "c"


def test_printable_input_filters_by_key_and_description():
    assert run_menu(
        "Title",
        _items(),
        key_source=_keys("se", Key.ENTER),
    ) == "b"


def test_backspace_removes_filter_and_escape_clears_before_backing_out():
    events = iter(("g", Key.BACKSPACE, Key.ESCAPE, Key.ESCAPE))

    assert run_menu("Title", _items(), key_source=lambda: next(events)) is None


def test_escape_with_filter_clears_filter_before_navigation():
    events = iter(("g", Key.ESCAPE, Key.DOWN, Key.ENTER))

    assert run_menu("Title", _items(), key_source=lambda: next(events)) == "b"


def test_filtered_navigation_skips_disabled_items():
    items = [
        MenuItem("a", "Alpha", enabled=False),
        MenuItem("b", "Beta"),
        MenuItem("c", "Gamma"),
    ]

    assert run_menu("Title", items, key_source=_keys("a", Key.ENTER)) == "b"


def test_filter_with_no_matches_does_not_activate_an_item():
    events = iter(("zzz", Key.ENTER, Key.ESCAPE, Key.ESCAPE))

    assert run_menu("Title", _items(), key_source=lambda: next(events)) is None


def test_filter_render_includes_filter_text_and_no_match_state():
    from blackoutkit import terminal_menu

    filtered = terminal_menu._build_panel(
        "Title",
        [],
        0,
        "guide",
        max_visible=3,
        filter_text="missing",
    )

    with terminal_menu.console.capture() as capture:
        terminal_menu.console.print(filtered)

    rendered = capture.get()
    assert "Filter: missing" in rendered
    assert "No matching items" in rendered


def test_narrow_console_uses_single_ellipsized_item_column(monkeypatch):
    from types import SimpleNamespace
    from blackoutkit import terminal_menu

    monkeypatch.setattr(
        terminal_menu,
        "console",
        SimpleNamespace(size=SimpleNamespace(width=30, height=12)),
    )

    panel = terminal_menu._build_panel(
        "Title",
        [MenuItem("long", "A very long label", "A very long description")],
        0,
        "guide",
    )

    assert len(panel.renderable.columns) == 2
    assert panel.renderable.columns[1].overflow == "ellipsis"
    assert panel.renderable.columns[1].no_wrap is True


def test_regular_console_keeps_label_and_description_columns(monkeypatch):
    from types import SimpleNamespace
    from blackoutkit import terminal_menu

    monkeypatch.setattr(
        terminal_menu,
        "console",
        SimpleNamespace(size=SimpleNamespace(width=100, height=30)),
    )

    panel = terminal_menu._build_panel("Title", _items(), 0, "guide")

    assert len(panel.renderable.columns) == 3
    assert panel.renderable.columns[1].width <= 32
    assert panel.renderable.columns[2].overflow == "ellipsis"


def test_filter_text_is_rendered_as_literal_markup(monkeypatch):
    import io
    from types import SimpleNamespace
    from rich.console import Console
    from blackoutkit import terminal_menu

    monkeypatch.setattr(
        terminal_menu,
        "console",
        SimpleNamespace(size=SimpleNamespace(width=80, height=20)),
    )
    panel = terminal_menu._build_panel(
        "Title",
        [],
        0,
        "guide",
        filter_text="[secret]",
    )
    stream = io.StringIO()
    Console(file=stream, width=80, color_system=None).print(panel)

    assert "[secret]" in stream.getvalue()
    assert "secret" in stream.getvalue()



def test_menu_viewport_recalculates_height_on_each_render(monkeypatch):
    from types import SimpleNamespace
    from blackoutkit import terminal_menu

    sizes = iter((SimpleNamespace(width=80, height=8), SimpleNamespace(width=80, height=20)))
    fake_console = SimpleNamespace(size=next(sizes))
    monkeypatch.setattr(terminal_menu, "console", fake_console)
    first = terminal_menu._build_panel("Title", _items() * 4, 0, "guide")
    fake_console.size = next(sizes)
    second = terminal_menu._build_panel("Title", _items() * 4, 0, "guide")

    assert len(first.renderable.rows) < len(second.renderable.rows)
    assert len(second.renderable.rows) == len(_items() * 4)
