from __future__ import annotations

from src.cli.main import parse_args


def test_cli_help():
    import sys
    try:
        parse_args(["--help"])
    except SystemExit:
        pass


def test_cli_list_checks():
    args = parse_args(["--list-checks"])
    assert args.list_checks is True


def test_cli_url_required():
    args = parse_args(["https://example.com"])
    assert args.url == "https://example.com"


def test_cli_custom_checks():
    args = parse_args(["https://example.com", "--checks", "headers,xss"])
    assert args.checks == "headers,xss"


def test_cli_output():
    args = parse_args(["https://example.com", "-o", "report.html", "-f", "json"])
    assert args.output == "report.html"
    assert args.format == "json"


def test_cli_version(capsys):
    try:
        parse_args(["--version"])
    except SystemExit:
        pass
