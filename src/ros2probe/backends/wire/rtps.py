import re
import struct

from pydantic import BaseModel, ConfigDict

RTPS_MAGIC = b"RTPS"
RTPS_HEADER_LEN = 20          # magic + version + vendorId + GUID prefix
SUBMESSAGE_HEADER_LEN = 4


# Submessage ids from the RTPS specification: names for display, sets for verdicts.
SUBMESSAGE_NAMES: dict[int, str] = {
    0x01: "PAD", 0x06: "ACKNACK", 0x07: "HEARTBEAT", 0x08: "GAP",
    0x09: "INFO_TS", 0x0C: "INFO_SRC", 0x0D: "INFO_REPLY_IP4",
    0x0E: "INFO_DST", 0x0F: "INFO_REPLY", 0x12: "NACK_FRAG",
    0x13: "HEARTBEAT_FRAG", 0x15: "DATA", 0x16: "DATA_FRAG",
    0x30: "SEC_BODY", 0x31: "SEC_PREFIX", 0x32: "SEC_POSTFIX",
    0x33: "SRTPS_PREFIX", 0x34: "SRTPS_POSTFIX",
}

DATA_IDS = frozenset({0x15, 0x16})
SUBMESSAGE_PROTECTION_IDS = frozenset({0x30, 0x31, 0x32})
RTPS_PROTECTION_IDS = frozenset({0x33, 0x34})
# RTPS 2.5 8.3.3.2.3: only for these does a zero length mean "empty, more follow".
EMPTY_WHEN_ZERO_LENGTH_IDS = frozenset({0x01, 0x09})

# SPDP bootstraps the handshake, so DDS-Security cannot protect it: never a finding.
SPDP_WRITER_ID = 0x000100C2
ENTITYID_UNKNOWN = 0x00000000
WRITER_ID_OFFSET = 12


def submessage_name(submessage_id: int) -> str:
    return SUBMESSAGE_NAMES.get(submessage_id, f"0x{submessage_id:02x}")


PRINTABLE_RUN_RE = re.compile(rb"[ -~]{5,}")
MAX_STRINGS_PER_PACKET = 24

# Strings that appear only in readable ROS 2 discovery or user data.
ROS_MARKERS: tuple[bytes, ...] = (
    b"rt/", b"rq/", b"rr/", b"ros_discovery_info", b"::dds_::",
    b"std_msgs", b"geometry_msgs", b"sensor_msgs", b"nav_msgs", b"tf2_msgs",
    b"DEFAULT_PARTICIPANT", b"enclave",
)


class RtpsPacket(BaseModel):
    """One decoded RTPS datagram."""
    model_config = ConfigDict(frozen=True)

    src: str
    dst: str
    src_port: int
    dst_port: int
    length: int
    submessages: tuple[int, ...] = ()
    data_writers: tuple[int, ...] = ()
    readable_strings: tuple[str, ...] = ()

    @property
    def submessage_names(self) -> tuple[str, ...]:
        return tuple(submessage_name(item) for item in self.submessages)

    @property
    def rtps_protected(self) -> bool:
        """Whole-message protection, so `rtps_protection_kind` is in force."""
        return bool(set(self.submessages) & RTPS_PROTECTION_IDS)

    @property
    def submessage_protected(self) -> bool:
        return bool(set(self.submessages) & SUBMESSAGE_PROTECTION_IDS)

    @property
    def spdp_only(self) -> bool:
        """Every DATA here is a participant announcement, which is never protected."""
        return bool(self.data_writers) and all(
            writer == SPDP_WRITER_ID for writer in self.data_writers
        )

    @property
    def has_plain_data(self) -> bool:
        """A DATA submessage in the open, with no protection wrapper around it."""
        if self.rtps_protected or self.submessage_protected:
            return False
        return any(writer != SPDP_WRITER_ID for writer in self.data_writers)

    @property
    def leaks_ros_names(self) -> bool:
        if self.spdp_only:
            return False
        joined = " ".join(self.readable_strings).encode("utf-8", "replace")
        return any(marker in joined for marker in ROS_MARKERS)

    def marker_strings(self) -> tuple[str, ...]:
        """Only the readable strings that actually identify ROS content."""
        found: list[str] = []
        for text in self.readable_strings:
            encoded = text.encode("utf-8", "replace")
            if any(marker in encoded for marker in ROS_MARKERS):
                found.append(text)
        return tuple(found)

    def describe(self) -> str:
        return (
            f"{self.src}:{self.src_port} -> {self.dst}:{self.dst_port} "
            f"{self.length}B submessages=[{', '.join(self.submessage_names)}]"
        )


def readable_strings(payload: bytes) -> tuple[str, ...]:
    found: list[str] = []
    for match in PRINTABLE_RUN_RE.finditer(payload):
        text = match.group(0).decode("ascii", "replace")
        if text not in found:
            found.append(text)
            if len(found) >= MAX_STRINGS_PER_PACKET:
                break
    return tuple(found)


def decode_submessages(payload: bytes) -> tuple[int, ...]:
    """Walk the submessage chain of one RTPS datagram."""
    return tuple(kind for kind, _ in decode_chain(payload))


def decode_data_writers(payload: bytes) -> tuple[int, ...]:
    """writerEntityId of every DATA and DATA_FRAG submessage, in chain order."""
    return tuple(writer for kind, writer in decode_chain(payload) if kind in DATA_IDS)


def decode_chain(payload: bytes) -> tuple[tuple[int, int], ...]:
    """(submessageId, writerEntityId) per submessage, ENTITYID_UNKNOWN if not read."""
    kinds: list[tuple[int, int]] = []
    offset = RTPS_HEADER_LEN
    while offset + SUBMESSAGE_HEADER_LEN <= len(payload):
        submessage_id = payload[offset]
        flags = payload[offset + 1]
        little_endian = bool(flags & 0x01)
        (next_header,) = struct.unpack_from(
            "<H" if little_endian else ">H", payload, offset + 2
        )
        writer = ENTITYID_UNKNOWN
        if submessage_id in DATA_IDS and offset + WRITER_ID_OFFSET + 4 <= len(payload):
            # EntityId_t is four octets, never swapped by the endianness flag.
            (writer,) = struct.unpack_from(">I", payload, offset + WRITER_ID_OFFSET)
        kinds.append((submessage_id, writer))
        if next_header == 0 and submessage_id not in EMPTY_WHEN_ZERO_LENGTH_IDS:
            break
        offset += SUBMESSAGE_HEADER_LEN + next_header
    return tuple(kinds)
