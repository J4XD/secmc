"""Wrapped tools; each module declares a PLUGIN."""

from secmcp.tools import ffuf, httpx, nmap, nuclei
from secmcp.tools.common import Plugin

PLUGINS: tuple[Plugin, ...] = (nmap.PLUGIN, httpx.PLUGIN, ffuf.PLUGIN, nuclei.PLUGIN)
