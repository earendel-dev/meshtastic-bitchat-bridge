"""Qt 6 (PySide6) front end for the Meshtastic <-> Bitchat bridge.

The GUI is only a shell: it starts the very same engine as the console
(``bridge.run``), reads its state and talks to it through a small, explicit
API.  Nothing here re-implements forwarding, binding or syncing rules.

Layout:

* ``main.py``            — entry point (``python -m gui``);
* ``window.py``          — the window: header, tabs, activity strip;
* ``core/session.py``    — engine lifecycle, asyncio loop in a worker thread;
* ``core/events.py``     — what the engine reports back to the user interface;
* ``pages/``             — one page per group of functions;
* ``pages/session_bridge.py`` — the actions a page may ask for;
* ``widgets/``           — reusable view pieces (live dot, counter, dialogs).

Test with ``gui_selftest.py`` in the repository root: it drives every
button, switch and split of the window without a radio or a phone.
"""
