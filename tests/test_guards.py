"""The safety nets in conftest.py really work."""

import os
import socket

import pytest

from lookfirst.core.http import github_token


def test_real_network_connections_are_blocked() -> None:
    with pytest.raises(RuntimeError, match="must not use the network"):
        socket.create_connection(("203.0.113.1", 443), timeout=1)  # a reserved test address


def test_dns_lookups_are_blocked() -> None:
    with pytest.raises(RuntimeError, match="must not use the network"):
        socket.getaddrinfo("example.com", 443)


def test_real_tokens_are_hidden_from_tests() -> None:
    assert "GITHUB_TOKEN" not in os.environ
    assert "GH_TOKEN" not in os.environ
    assert github_token() is None
