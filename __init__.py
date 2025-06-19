"""
kbfi

A toolkit for WiFi network scanning, client discovery, and vendor lookup.
This module provides a unified interface for scanning WiFi networks, discovering connected clients, and performing vendor lookups using MAC addresses.

Public API:
- KbfiToolkit: Main toolkit class for scanning and vendor lookup
- get_vendor: Function to look up vendor from MAC address
- VendorDatabase: Class for managing the OUI/vendor database
- WifiNetwork: Data class representing a WiFi network
- MacAddress: Data class representing a MAC address
"""

from .kbfi import (
    KbfiToolkit,      # Main toolkit class
    get_vendor,       # Vendor lookup function
    VendorDatabase,   # OUI/vendor database manager
    WifiNetwork,      # WiFi network data class
    MacAddress,       # MAC address data class
)

__version__ = "0.1.0"
__author__ = "Kaustubh Bhattacharyya"
__email__ = "kb01tech@gmail.com"

__all__ = [
    "KbfiToolkit",
    "get_vendor",
    "VendorDatabase",
    "WifiNetwork",
    "MacAddress",
]