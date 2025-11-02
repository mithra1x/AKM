"""Tests for the DoubleThink CLI helpers."""

import argparse

import pytest

from doublethink.cli import _dispatch, _is_http_url
from doublethink.rules import default_rulebook


def make_args(**kwargs):
    defaults = {"command": None, "target": None, "origin": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_is_http_url():
    assert _is_http_url("https://example.com/path")
    assert not _is_http_url("not-a-url")


def test_dispatch_rejects_non_url_for_url_command():
    rulebook = default_rulebook()
    args = make_args(command="url", target="/tmp/file.html")
    with pytest.raises(ValueError):
        _dispatch(args, rulebook)


def test_dispatch_rejects_url_for_file_command():
    rulebook = default_rulebook()
    args = make_args(command="file", target="https://example.com")
    with pytest.raises(ValueError):
        _dispatch(args, rulebook)
