import pytest

from iotsec.sanitize import (
    clean_domain,
    clean_text,
    domain_label_entropy,
    is_randomized_mac,
    is_unicast_mac,
    normalize_mac,
    shannon_entropy,
    valid_interface,
    valid_ip,
)


def test_clean_text_strips_markup_and_control_characters():
    assert clean_text('<script>alert("x")</script>\x00\x1b[31m') == "scriptalert(x)/script31m"
    assert clean_text("a" * 500, 10) == "a" * 10
    assert clean_text("  many   spaces\t\n") == "many spaces"
    assert clean_text(b"bytes \xff value") == "bytes � value"
    assert clean_text("") is None and clean_text(None) is None


def test_clean_domain():
    assert clean_domain("Update.Example.COM.") == "update.example.com"
    assert clean_domain("evil<>.test") == "evil.test"
    assert len(clean_domain("a" * 400)) == 253
    assert clean_domain("...") is None and clean_domain("") is None


@pytest.mark.parametrize("value,expected", [
    ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
    ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
    ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
    ("aa:bb:cc:dd:ee", None),
    ("zz:bb:cc:dd:ee:ff", None),
    ("aa:bb:cc:dd:ee:ff; rm -rf /", None),
])
def test_normalize_mac(value, expected):
    assert normalize_mac(value) == expected


def test_mac_properties():
    assert is_randomized_mac("3a:00:00:00:00:01") and not is_randomized_mac("44:19:b6:00:00:01")
    assert not is_unicast_mac("ff:ff:ff:ff:ff:ff") and not is_unicast_mac("01:00:5e:00:00:fb")
    assert is_unicast_mac("44:19:b6:00:00:01") and not is_unicast_mac(None)


def test_valid_ip():
    assert valid_ip(" 192.168.1.1 ") == "192.168.1.1"
    assert valid_ip("2001:db8::1") == "2001:db8::1"
    assert valid_ip("192.168.1.1; drop") is None and valid_ip("") is None


@pytest.mark.parametrize("name", ["eth0", "wlan0", "br-lan", "enp3s0.100", "veth@if2"])
def test_valid_interfaces(name):
    assert valid_interface(name) == name


@pytest.mark.parametrize("name", ["", "-i", "--help", "eth0 -w /tmp/x", "a" * 16, "eth0;id"])
def test_invalid_interfaces(name):
    with pytest.raises(ValueError):
        valid_interface(name)


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
    assert domain_label_entropy("x8f7ghq2kd9s7f6.evil.test") > 3.5
    assert domain_label_entropy("www.example.com") < 2
