import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


resolver = load_module("country_resolver", ROOT / "scripts/country_resolver.py")
collector = load_module("collector", ROOT / "scripts/update_catalog.py")

# Explicit node metadata is resolved by the dedicated resolver.
cases = [
    ("#Germany-01", "DE"),
    ("#Singapore-02", "SG"),
    ("Canada.txt", "CA"),
    ("United States", "US"),
    ("node-DE-01", "DE"),
]

for value, expected in cases:
    got = resolver.extract_country_from_text(value)
    assert got == expected, (value, got, expected)

# Never infer a country from arbitrary two-letter text or transport tokens.
assert resolver.extract_country_from_text("ws tls tcp") is None
assert resolver.extract_country_from_text("some-host.us.example") is None
assert resolver.extract_country_from_text("ZZ") is None

# Explicit country metadata still works when presented as a bare ISO code.
assert resolver.extract_country_from_text("DE") == "DE"
assert resolver.extract_country_from_text("Canada.txt") == "CA"

# Collector parsing/endpoint behavior remains covered independently.
assert collector.protocol_from_uri("vless://x@y:443") == "vless"
assert collector.protocol_from_uri("ss://x@y:443") == "shadowsocks"
assert (
    collector.endpoint_from_uri(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws#Germany"
    )[1]
    == 443
)

# Source filename hints are intentionally not part of final country resolution:
# country is assigned only after successful Xray health checks and resolution.
print("country/protocol/endpoint tests: PASS")
