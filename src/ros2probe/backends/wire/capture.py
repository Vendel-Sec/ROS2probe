import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ...targets.profile import WireSettings
from .pcap import read_udp_datagrams
from .rtps import (
    RTPS_MAGIC,
    RtpsPacket,
    decode_data_writers,
    decode_submessages,
    readable_strings,
)

MAX_LEAKED_NAMES = 12
MAX_SAMPLE_PACKETS = 6

LOG = logging.getLogger(__name__)


class Capture(BaseModel):
    """A decoded capture, plus how it was obtained."""
    model_config = ConfigDict(frozen=True)

    source: str
    packets: tuple[RtpsPacket, ...] = ()
    total_datagrams: int = 0
    error: str = ""
    notes: tuple[str, ...] = ()

    @property
    def rtps_count(self) -> int:
        return len(self.packets)

    @property
    def usable(self) -> bool:
        return self.rtps_count > 0

    @property
    def plaintext_packets(self) -> tuple[RtpsPacket, ...]:
        return tuple(packet for packet in self.packets if packet.has_plain_data)

    @property
    def protected_packets(self) -> tuple[RtpsPacket, ...]:
        return tuple(
            packet for packet in self.packets
            if packet.rtps_protected or packet.submessage_protected
        )

    @property
    def rtps_protected_packets(self) -> tuple[RtpsPacket, ...]:
        return tuple(packet for packet in self.packets if packet.rtps_protected)

    @property
    def spdp_only_packets(self) -> tuple[RtpsPacket, ...]:
        """Participant announcements, plaintext on every robot."""
        return tuple(packet for packet in self.packets if packet.spdp_only)

    def why_undecidable(self) -> str:
        """Why a capture holds no judgeable traffic, for the skip reason."""
        spdp = len(self.spdp_only_packets)
        if spdp:
            return (f"{self.rtps_count} datagram(s), {spdp} of them SPDP, which "
                    "DDS-Security never protects")
        return f"{self.rtps_count} datagram(s), no DATA in plain or protected form"

    @property
    def carries_samples(self) -> bool:
        """Whether the capture holds DATA at all, plain or protected."""
        return bool(self.plaintext_packets or self.protected_packets)

    @property
    def name_leaking_packets(self) -> tuple[RtpsPacket, ...]:
        return tuple(packet for packet in self.packets if packet.leaks_ros_names)

    def spdp_exposure(self, limit: int = MAX_LEAKED_NAMES) -> tuple[str, ...]:
        """Enclave and node paths a passive listener reads off clear-text SPDP."""
        found: list[str] = []
        for packet in self.spdp_only_packets:
            for text in packet.readable_strings:
                if (text.startswith("/") or "enclave" in text) and text not in found:
                    found.append(text)
                    if len(found) >= limit:
                        return tuple(found)
        return tuple(found)

    def leaked_names(self, limit: int = MAX_LEAKED_NAMES) -> tuple[str, ...]:
        """The actual strings a passive attacker would have read off the wire."""
        found: list[str] = []
        for packet in self.name_leaking_packets:
            for text in packet.marker_strings():
                if text not in found:
                    found.append(text)
                    if len(found) >= limit:
                        return tuple(found)
        return tuple(found)

    def sample(self, packets: tuple[RtpsPacket, ...]) -> str:
        return "\n".join(
            f"    {packet.describe()}" for packet in packets[:MAX_SAMPLE_PACKETS]
        )

    def summary(self) -> str:
        return (
            f"{self.rtps_count} RTPS datagram(s) of {self.total_datagrams} captured "
            f"from {self.source}: {len(self.rtps_protected_packets)} whole-message "
            f"protected, {len(self.protected_packets)} protected at any level, "
            f"{len(self.plaintext_packets)} carrying plain DATA"
        )


def decode(path: Path, source: str) -> Capture:
    contents = read_udp_datagrams(path)
    if contents.error:
        return Capture(source=source, error=contents.error)

    packets = tuple(
        RtpsPacket(
            src=datagram.src, dst=datagram.dst,
            src_port=datagram.src_port, dst_port=datagram.dst_port,
            length=len(datagram.payload),
            submessages=decode_submessages(datagram.payload),
            data_writers=decode_data_writers(datagram.payload),
            readable_strings=readable_strings(datagram.payload),
        )
        for datagram in contents.datagrams
        if datagram.payload.startswith(RTPS_MAGIC)
    )
    return Capture(
        source=source, packets=packets, total_datagrams=contents.total_frames,
        notes=(f"link type {contents.link_type_name}",),
    )


def take_capture(
    settings: WireSettings, destination: Path | None = None,
) -> Capture:
    """Run tcpdump for the configured window.

    `destination` saves the pcap file
    """
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        return Capture(source="live capture", error="tcpdump is not installed")

    capture_filter = settings.capture_filter
    if destination is None:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
            destination = Path(handle.name)

    argv = [
        tcpdump, "-i", settings.interface, "-w", str(destination),
        "-c", str(settings.max_packets), "-U", "-n", "-s", "0",
        capture_filter,
    ]
    try:
        subprocess.run(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=settings.capture_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        pass                               # the timeout IS the capture window
    except OSError as exc:
        return Capture(source="live capture", error=f"cannot run tcpdump: {exc}")

    decoded = decode(destination, "live capture")
    notes = [
        f"captured for {settings.capture_seconds}s on interface "
        f"{settings.interface}, filter {capture_filter}",
        *decoded.notes,
    ]
    if not decoded.usable and not decoded.error:
        notes.append(
            "no RTPS seen. Discovery may have completed before the capture "
            "started, or the interface is wrong. Restarting the target during the "
            "capture window is the reliable way to see discovery."
        )
    return decoded.model_copy(update={"notes": tuple(notes)})


def capture_or_load(
    settings: WireSettings, destination: Path | None = None,
) -> Capture:
    """Decode a supplied pcap if there is one, otherwise take a live capture."""
    if settings.pcap is not None:
        if destination is not None and settings.pcap != destination:
            shutil.copy2(settings.pcap, destination)
        taken = decode(settings.pcap, str(settings.pcap))
    else:
        taken = take_capture(settings, destination=destination)
    LOG.debug("%s", taken)
    return taken
