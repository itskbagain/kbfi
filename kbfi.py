"""
kbfi.kbfi

WiFi and MAC address scanning toolkit with vendor lookup capabilities.
Provides scanning for WiFi networks and clients, vendor lookup, and export utilities.
"""
import os
import platform
import subprocess
import re
import json
import csv
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional, Callable, Any, Type, Union, Set, Tuple, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import threading

try:
    import requests
except ImportError:
    raise ImportError("Please install the 'requests' package: pip install requests")

def command_exists(cmd: str) -> bool:
    """Check if a command exists in the system PATH."""
    from shutil import which
    return which(cmd) is not None

# --- Logging ---
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("kbfi")

# --- Constants ---
DEFAULT_TIMEOUT = 30
OUI_UPDATE_INTERVAL = 86400 * 7  # 7 days
DEFAULT_CACHE_DIR = Path.home() / ".local" / "share" / "kbfi"

# --- Data Models ---
@dataclass(frozen=True)
class WifiNetwork:
    """Represents a WiFi network."""
    ssid: str
    bssid: str
    signal: int
    channel: Optional[int] = None
    frequency: Optional[float] = None
    encryption: str = "Unknown"
    vendor: Optional[str] = None
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def __post_init__(self):
        object.__setattr__(self, "first_seen", self.first_seen or time.time())
        object.__setattr__(self, "last_seen", time.time())

    @property
    def signal_quality(self) -> str:
        """Return human-readable signal quality."""
        if self.signal >= -30:
            return "Excellent"
        elif self.signal >= -50:
            return "Very Good"
        elif self.signal >= -60:
            return "Good"
        elif self.signal >= -70:
            return "Fair"
        else:
            return "Weak"

    @property
    def security_level(self) -> str:
        enc = self.encryption.upper()
        if "WPA3" in enc:
            return "Very High"
        elif "WPA2" in enc:
            return "High"
        elif "WPA" in enc:
            return "Medium"
        elif "WEP" in enc:
            return "Low"
        else:
            return "None"

@dataclass(frozen=True)
class MacAddress:
    """Represents a MAC address with vendor info."""
    mac: str
    vendor: Optional[str] = None
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def __post_init__(self):
        object.__setattr__(self, "first_seen", self.first_seen or time.time())
        object.__setattr__(self, "last_seen", time.time())

# --- Exceptions ---
class WifiScannerError(Exception): pass
class InterfaceNotFoundError(WifiScannerError): pass
class ScanFailedError(WifiScannerError): pass
class VendorLookupError(WifiScannerError): pass

# --- OUI/Vendor Lookup ---
class VendorDatabase:
    """Manages OUI database for vendor lookups."""

    def __init__(self, cache_dir: Path = DEFAULT_CACHE_DIR):
        self.cache_dir = Path(cache_dir)
        self.cache_file = self.cache_dir / "oui.txt"
        self.metadata_file = self.cache_dir / "oui_metadata.json"
        self._oui_db: Optional[Dict[str, str]] = None
        self._lock = threading.RLock()

    def _ensure_cache_dir(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _is_cache_stale(self) -> bool:
        if not self.cache_file.exists() or not self.metadata_file.exists():
            return True
        try:
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
            last_update = metadata.get('last_update', 0)
            return time.time() - last_update > OUI_UPDATE_INTERVAL
        except Exception:
            return True

    def update_database(self, force: bool = False) -> bool:
        """Update OUI database from IEEE registry."""
        if not force and not self._is_cache_stale():
            return False
        self._ensure_cache_dir()
        url = "https://standards-oui.ieee.org/oui/oui.txt"
        try:
            logger.info("Updating OUI database...")
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            metadata = {
                'last_update': time.time(),
                'url': url,
                'size': len(response.text)
            }
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f)
            with self._lock:
                self._oui_db = None
            logger.info("OUI database updated.")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to update OUI database: {e}")
            if not self.cache_file.exists():
                raise VendorLookupError(f"Cannot update OUI database and no cache exists: {e}")
            logger.warning("Using cached OUI database")
            return False

    def load_database(self) -> Dict[str, str]:
        with self._lock:
            if self._oui_db is not None:
                return self._oui_db
            try:
                self.update_database()
            except VendorLookupError:
                pass
            if not self.cache_file.exists():
                raise VendorLookupError("OUI database not available and cannot be downloaded")
            db = {}
            with open(self.cache_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.match(r'^([0-9A-Fa-f\-]{8})\s+\(base 16\)\s+(.+)', line.strip())
                    if match:
                        oui_hex = match.group(1).replace('-', ':')
                        vendor = match.group(2).strip()
                        db[oui_hex] = vendor
            self._oui_db = db
            logger.info(f"Loaded {len(db)} OUI entries")
            return db

    def lookup_vendor(self, mac: str) -> str:
        """Look up vendor for a MAC address."""
        try:
            mac_clean = re.sub(r'[^0-9A-Fa-f]', '', mac.upper())
            if len(mac_clean) < 6:
                return "Invalid MAC"
            oui = mac_clean[:6]
            oui_formatted = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
            db = self.load_database()
            return db.get(oui_formatted, "Unknown")
        except Exception as e:
            logger.error(f"Vendor lookup failed for {mac}: {e}")
            return "Lookup Failed"

_vendor_db = VendorDatabase()
def get_vendor(mac: str) -> str:
    """Convenience function for vendor lookup."""
    return _vendor_db.lookup_vendor(mac)
def update_vendor_database(force: bool = False) -> bool:
    """Update vendor database."""
    return _vendor_db.update_database(force)

# --- Result Collections ---
class ScanResultCollection(list):
    """Base class for scan result collections with filtering and export capabilities."""

    def filter(self, predicate: Callable[[Any], bool]) -> "ScanResultCollection":
        return self.__class__([obj for obj in self if predicate(obj)])

    def sort_by(self, key: Union[str, Callable[[Any], Any]], reverse: bool = False) -> "ScanResultCollection":
        if isinstance(key, str):
            return self.__class__(sorted(self, key=lambda o: getattr(o, key, ""), reverse=reverse))
        else:
            return self.__class__(sorted(self, key=key, reverse=reverse))

    def as_dicts(self) -> List[Dict]:
        return [asdict(obj) for obj in self]

    def export_json(self, filename: str) -> None:
        with open(filename, "w") as f:
            json.dump(self.as_dicts(), f, indent=2)

    def export_csv(self, filename: str) -> None:
        if not self:
            return
        with open(filename, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=self[0].__dataclass_fields__.keys())
            w.writeheader()
            for obj in self:
                w.writerow(asdict(obj))

class WifiNetworkCollection(ScanResultCollection):
    def with_vendors(self, threaded: bool = True) -> "WifiNetworkCollection":
        def add_vendor(n: WifiNetwork) -> WifiNetwork:
            return WifiNetwork(**{**asdict(n), "vendor": get_vendor(n.bssid)})
        if threaded:
            with ThreadPoolExecutor() as pool:
                return WifiNetworkCollection(list(pool.map(add_vendor, self)))
        else:
            return WifiNetworkCollection([add_vendor(n) for n in self])

class MacAddressCollection(ScanResultCollection):
    def with_vendors(self, threaded: bool = True) -> "MacAddressCollection":
        def add_vendor(m: MacAddress) -> MacAddress:
            return MacAddress(**{**asdict(m), "vendor": get_vendor(m.mac)})
        if threaded:
            with ThreadPoolExecutor() as pool:
                return MacAddressCollection(list(pool.map(add_vendor, self)))
        else:
            return MacAddressCollection([add_vendor(m) for m in self])

# --- Scanner Backends ---
class ScannerBackend(ABC):
    """Abstract base class for scanner backends."""
    @abstractmethod
    def scan_networks(self, interface: str) -> WifiNetworkCollection: pass
    @abstractmethod
    def scan_clients(self, interface: str) -> MacAddressCollection: pass

class LinuxBackend(ScannerBackend):
    def scan_networks(self, interface: str) -> WifiNetworkCollection:
        if command_exists("iwlist"):
            return self._scan_with_iwlist(interface)
        elif command_exists("nmcli"):
            return self._scan_with_nmcli()
        else:
            raise ScanFailedError("No supported scanning tool found (iwlist or nmcli required)")

    def _scan_with_iwlist(self, interface: str) -> WifiNetworkCollection:
        try:
            output = subprocess.check_output(
                ["iwlist", interface, "scan"],
                stderr=subprocess.DEVNULL,
                timeout=DEFAULT_TIMEOUT
            ).decode(errors='ignore')
            networks = []
            for cell in output.split("Cell "):
                if "Address:" not in cell:
                    continue
                n = self._parse_iwlist_cell(cell)
                if n:
                    networks.append(n)
            return WifiNetworkCollection(networks)
        except Exception as e:
            raise ScanFailedError(f"iwlist scan failed: {e}")

    def _parse_iwlist_cell(self, cell: str) -> Optional[WifiNetwork]:
        try:
            bssid = re.search(r"Address: ([\dA-Fa-f:]+)", cell)
            ssid = re.search(r'ESSID:"([^"]*)"', cell)
            signal = re.search(r"Signal level=([-0-9]+)", cell)
            channel = re.search(r"Channel:(\d+)", cell)
            freq = re.search(r"Frequency:([\d\.]+)", cell)
            encryption = "Open"
            for key in ["WPA3", "WPA2", "WPA", "WEP"]:
                if key in cell: encryption = key; break
            return WifiNetwork(
                ssid=ssid.group(1) if ssid else "",
                bssid=bssid.group(1) if bssid else "",
                signal=int(signal.group(1)) if signal else -100,
                channel=int(channel.group(1)) if channel else None,
                frequency=float(freq.group(1)) if freq else None,
                encryption=encryption
            )
        except Exception as e:
            logger.debug(f"Failed to parse iwlist cell: {e}")
            return None

    def _scan_with_nmcli(self) -> WifiNetworkCollection:
        try:
            output = subprocess.check_output([
                "nmcli", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN,FREQ",
                "device", "wifi", "list"
            ], timeout=DEFAULT_TIMEOUT).decode(errors='ignore')
            networks = []
            lines = output.strip().split('\n')[1:]  # Skip header
            for line in lines:
                n = self._parse_nmcli_line(line)
                if n:
                    networks.append(n)
            return WifiNetworkCollection(networks)
        except Exception as e:
            raise ScanFailedError(f"nmcli scan failed: {e}")

    def _parse_nmcli_line(self, line: str) -> Optional[WifiNetwork]:
        try:
            bssid = re.search(r'([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})', line)
            signal = re.search(r'\s(\d+)\s', line)
            ssid = line.split(bssid.group(1))[0].strip() if bssid else ""
            encryption = "Open"
            for key in ["WPA3", "WPA2", "WPA", "WEP"]:
                if key in line: encryption = key; break
            return WifiNetwork(
                ssid=ssid,
                bssid=bssid.group(1) if bssid else "",
                signal=int(signal.group(1)) if signal else -100,
                encryption=encryption
            )
        except Exception as e:
            logger.debug(f"Failed to parse nmcli line: {e}")
            return None

    def scan_clients(self, interface: str) -> MacAddressCollection:
        macs: Set[str] = set()
        if command_exists("iw"):
            try:
                output = subprocess.check_output(
                    ["iw", interface, "station", "dump"],
                    stderr=subprocess.DEVNULL,
                    timeout=DEFAULT_TIMEOUT
                ).decode(errors='ignore')
                for line in output.splitlines():
                    if "Station" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            macs.add(parts[1])
            except Exception: pass
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", 'r') as f:
                    for line in f:
                        mac_match = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', line)
                        if mac_match:
                            macs.add(mac_match.group(0))
            except Exception: pass
        return MacAddressCollection([MacAddress(mac=m) for m in macs])

class WindowsBackend(ScannerBackend):
    def scan_networks(self, interface: str) -> WifiNetworkCollection:
        try:
            output = subprocess.check_output(
                "netsh wlan show networks mode=Bssid",
                shell=True,
                timeout=DEFAULT_TIMEOUT
            ).decode(errors='ignore')
            networks = []
            blocks = output.split("SSID ")[1:]
            for block in blocks:
                n = self._parse_netsh_block(block)
                if n: networks.append(n)
            return WifiNetworkCollection(networks)
        except Exception as e:
            raise ScanFailedError(f"netsh scan failed: {e}")

    def _parse_netsh_block(self, block: str) -> Optional[WifiNetwork]:
        try:
            ssid = re.search(r": (.+)", block)
            bssid = re.search(r"BSSID 1\s*:\s*([\dA-Fa-f:]+)", block)
            signal_pct = re.search(r"Signal\s*:\s*(\d+)%", block)
            enc = re.search(r"Authentication\s*:\s*(.+)", block)
            signal = -100 + (int(signal_pct.group(1)) * 70 // 100) if signal_pct else -100
            return WifiNetwork(
                ssid=ssid.group(1).strip() if ssid else "",
                bssid=bssid.group(1) if bssid else "",
                signal=signal,
                encryption=enc.group(1).strip() if enc else "Open"
            )
        except Exception as e:
            logger.debug(f"Failed to parse netsh block: {e}")
            return None

    def scan_clients(self, interface: str) -> MacAddressCollection:
        try:
            output = subprocess.check_output(
                "arp -a",
                shell=True,
                timeout=DEFAULT_TIMEOUT
            ).decode(errors='ignore')
            macs = set(re.findall(r"([0-9a-fA-F]{2}(?:[-:])){5}[0-9a-fA-F]{2}", output))
            return MacAddressCollection([MacAddress(mac=m) for m in macs])
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            return MacAddressCollection([])

# --- Auto Backend Detection ---
def _detect_backend() -> Type[ScannerBackend]:
    plat = platform.system().lower()
    if plat == "windows":
        return WindowsBackend
    elif plat in ["linux", "darwin"]:
        return LinuxBackend
    else:
        raise WifiScannerError(f"Unsupported platform: {plat}")

def get_default_interface() -> Optional[str]:
    """Try to detect the default wireless interface."""
    plat = platform.system().lower()
    if plat == "windows":
        try:
            output = subprocess.check_output(
                "netsh wlan show interfaces",
                shell=True,
                timeout=DEFAULT_TIMEOUT
            ).decode(errors='ignore')
            match = re.search(r"^\s*Name\s*:\s*(.+)$", output, re.MULTILINE)
            if match:
                return match.group(1).strip()
        except Exception:
            return None
    elif plat in ["linux", "darwin"]:
        try:
            output = subprocess.check_output(
                ["iwconfig"],
                stderr=subprocess.DEVNULL,
                timeout=DEFAULT_TIMEOUT
            ).decode(errors='ignore')
            matches = re.findall(r"^([a-zA-Z0-9]+)\s+IEEE 802.11", output, re.MULTILINE)
            if matches:
                return matches[0]
        except Exception:
            pass
        # Try nmcli as fallback
        try:
            output = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device"],
                timeout=DEFAULT_TIMEOUT
            ).decode(errors='ignore')
            for line in output.splitlines():
                dev, typ = line.split(":")
                if typ == "wifi":
                    return dev
        except Exception:
            pass
    return None

# --- Main Scanner API ---
class KbfiToolkit:
    """Unified WiFi/MAC scanner interface (kbfi)."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or get_default_interface()
        if not self.interface:
            raise InterfaceNotFoundError("No wireless interfaces found")
        self.backend: ScannerBackend = _detect_backend()()

    def scan_wifi(self) -> WifiNetworkCollection:
        """Scan for WiFi networks on the interface."""
        if self.interface is None:
            raise InterfaceNotFoundError("No wireless interface specified")
        return self.backend.scan_networks(self.interface)

    def scan_clients(self) -> MacAddressCollection:
        """Scan for MAC addresses of connected clients."""
        if self.interface is None:
            raise InterfaceNotFoundError("No wireless interface specified")
        return self.backend.scan_clients(self.interface)

    def vendor_db(self) -> VendorDatabase:
        """Access the vendor database manager."""
        return _vendor_db

def main() -> None:
    """Main entry point for the CLI."""
    import argparse
    import sys
    from datetime import datetime

    parser = argparse.ArgumentParser(
        description="kbfi - Scan networks and MAC addresses with vendor lookup"
    )
    parser.add_argument(
        "--interface", "-i",
        help="Wireless interface to use (default: auto-detect)"
    )
    parser.add_argument(
        "--scan-type", "-t",
        choices=["wifi", "clients", "both"],
        default="both",
        help="Type of scan to perform (default: both)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "text"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--update-vendor-db", "-u",
        action="store_true",
        help="Update vendor database before scanning"
    )
    parser.add_argument(
        "--min-signal", "-s",
        type=int,
        default=-100,
        help="Minimum signal strength to include (default: -100)"
    )

    args = parser.parse_args()

    try:
        if args.update_vendor_db:
            print("Updating vendor database...")
            update_vendor_database(force=True)

        tk = KbfiToolkit(interface=args.interface)
        
        results = []
        if args.scan_type in ["wifi", "both"]:
            print("Scanning WiFi networks...")
            networks = tk.scan_wifi().with_vendors()
            networks = networks.filter(lambda n: n.signal >= args.min_signal)
            results.append(("networks", networks))
            
        if args.scan_type in ["clients", "both"]:
            print("Scanning connected clients...")
            clients = tk.scan_clients().with_vendors()
            results.append(("clients", clients))

        if args.output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if args.format == "json":
                for name, data in results:
                    filename = f"{args.output}_{name}_{timestamp}.json"
                    data.export_json(filename)
                    print(f"Results saved to {filename}")
            elif args.format == "csv":
                for name, data in results:
                    filename = f"{args.output}_{name}_{timestamp}.csv"
                    data.export_csv(filename)
                    print(f"Results saved to {filename}")
        else:
            for name, data in results:
                print(f"\n=== {name.upper()} ===")
                if args.format == "json":
                    print(json.dumps(data.as_dicts(), indent=2))
                elif args.format == "csv":
                    import io
                    output = io.StringIO()
                    data.export_csv(output)
                    print(output.getvalue())
                else:  # text format
                    for item in data:
                        if isinstance(item, WifiNetwork):
                            print(f"SSID: {item.ssid}")
                            print(f"BSSID: {item.bssid}")
                            print(f"Signal: {item.signal} dBm ({item.signal_quality})")
                            print(f"Channel: {item.channel}")
                            print(f"Encryption: {item.encryption}")
                            print(f"Vendor: {item.vendor}")
                            print("---")
                        else:  # MacAddress
                            print(f"MAC: {item.mac}")
                            print(f"Vendor: {item.vendor}")
                            print("---")

    except WifiScannerError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        sys.exit(130)

if __name__ == "__main__":
    main()