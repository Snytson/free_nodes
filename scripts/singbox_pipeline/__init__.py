"""sing-box based collection, probing and catalog publication.

The package deliberately keeps share links as the published artifact. Share
links are converted to sing-box outbounds only for testing; no generated
credential or transport field is written back to the catalog.
"""

__all__ = ["share_link", "config", "probe", "runner", "collect", "finalize"]
