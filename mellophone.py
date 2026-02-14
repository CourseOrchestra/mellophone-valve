from __future__ import annotations

import sys

from src.mellophone import client as _client

sys.modules[__name__] = _client
