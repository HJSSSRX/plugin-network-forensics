from __future__ import annotations

"""network-forensics Cell — tests."""

from plugin import NetworkForensicsPlugin


def test_plugin_registers_tools():
    plugin = NetworkForensicsPlugin()
    tools = plugin.register_tools()
    assert len(tools) >= 1
    assert all(t.name for t in tools)
    assert all(t.domain for t in tools)
    assert all(t.risk_level in ("LOW", "MEDIUM", "HIGH") for t in tools)


def test_plugin_metadata():
    plugin = NetworkForensicsPlugin()
    assert plugin.name == "network-forensics"
    assert plugin.version
    assert plugin.domain == "network"
