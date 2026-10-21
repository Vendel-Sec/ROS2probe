import logging
from pathlib import Path

from pydantic import BaseModel, ConfigDict
from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, UDP, defragment
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

logging.getLogger("scapy").setLevel(logging.ERROR)


class UdpDatagram(BaseModel):
    model_config = ConfigDict(frozen=True)

    src: str
    dst: str
    src_port: int
    dst_port: int
    payload: bytes


class PcapContents(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: Path
    link_type_name: str = ""
    total_frames: int = 0
    datagrams: tuple[UdpDatagram, ...] = ()
    error: str = ""


def _link_type_names(reader: PcapReader) -> str:
    # A pcap carries one linktype on the file header, a pcapng one per interface.
    interfaces = getattr(reader, "interfaces", None)
    if interfaces is not None:
        link_types = sorted({entry[0] for entry in interfaces})
    else:
        link_types = [getattr(reader, "linktype", None)]

    names = []
    for link_type in link_types:
        layer = conf.l2types.num2layer.get(link_type) if link_type is not None else None
        if layer is not None:
            names.append(f"{layer.__name__} ({link_type})")
        elif link_type is not None:
            names.append(f"linktype {link_type}")
    return ", ".join(names) or "unknown"


def read_udp_datagrams(path: Path) -> PcapContents:
    try:
        with PcapReader(str(path)) as reader:
            frames = reader.read_all()
            link_type_name = _link_type_names(reader)
    except FileNotFoundError:
        return PcapContents(path=path, error=f"capture not found: {path}")
    except OSError as exc:
        return PcapContents(path=path, error=f"cannot read capture: {exc}")
    except Scapy_Exception as exc:
        return PcapContents(path=path, error=f"not a pcap or pcapng file: {exc}")

    datagrams = tuple(
        UdpDatagram(
            src=frame[IPv6].src if IPv6 in frame else frame[IP].src,
            dst=frame[IPv6].dst if IPv6 in frame else frame[IP].dst,
            src_port=frame[UDP].sport,
            dst_port=frame[UDP].dport,
            payload=bytes(frame[UDP].payload),
        )
        for frame in defragment(frames)
        if UDP in frame and (IP in frame or IPv6 in frame)
    )
    return PcapContents(
        path=path,
        link_type_name=link_type_name,
        total_frames=len(frames),
        datagrams=datagrams,
    )
