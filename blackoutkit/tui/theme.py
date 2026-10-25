# blackoutkit/tui/theme.py
"""Blackout Console tactical theme (dark) + light variant."""
DARK_CSS = """
Screen {
    background: #0c0d10;
    color: #ECEFF4;
}
Static#dash-hint {
    color: #8B949E;
    padding: 0 1;
}
ListView {
    background: #0E1015;
}
ListItem {
    padding: 0 1;
}
ListView > ListItem.--highlight {
    background: #172230;
}
Button {
    background: #171A23;
    border: round #252A36;
}
Button:hover {
    border: round #00E5FF;
}
Tabs {
    background: #0E1015;
}
Tabs > .tabs--highlight {
    color: #00E5FF;
}
Input {
    border: round #252A36;
}
Input:focus {
    border: round #00E5FF;
}
CollapsibleTitle {
    color: #00E5FF;
}
Footer {
    background: #0E1015;
}
QuitConfirmScreen {
    align: center middle;
}
#confirm-dialog {
    padding: 1 2;
    width: 60;
    height: auto;
    border: thick #FF5555;
    background: #171A23;
}
#confirm-msg {
    margin-bottom: 1;
}
"""

LIGHT_CSS = """
Screen {
    background: #F4F6F9;
    color: #10141B;
}
"""
