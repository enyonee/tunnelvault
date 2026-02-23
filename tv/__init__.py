"""tunnelvault - multi-VPN connection manager."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("tunnelvault")
except PackageNotFoundError:
    __version__ = "dev"
