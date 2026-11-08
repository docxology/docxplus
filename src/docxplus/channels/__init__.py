"""docxplus intelligence channels and the channel registry."""

from __future__ import annotations

from .base import Channel, ChannelRecord
from .custom_xml import CustomXmlChannel
from .mce import MceChannel
from .metadata import MetadataChannel, OdtMetadataChannel
from .package_part import PackagePartChannel
from .stego_media import StegMediaChannel

# Channels that need no optional/external toolchain; safe to construct anywhere.
_PURE_CHANNELS: dict[str, type] = {
    CustomXmlChannel.id: CustomXmlChannel,
    PackagePartChannel.id: PackagePartChannel,
    MetadataChannel.id: MetadataChannel,
    MceChannel.id: MceChannel,
}

#: Profile-specific ids. They extract correctly through ``get_channel`` but are
#: deliberately absent from ``available_channels`` so the OOXML authoring surface
#: cannot mint a record the ODF reader alone understands.
_ODT_ONLY_CHANNELS: dict[str, type] = {
    OdtMetadataChannel.id: OdtMetadataChannel,
}


def get_channel(channel_id: str, **kwargs) -> Channel:
    """Instantiate a channel by id.

    ``stego_media`` is handled separately because it takes carrier/signing config
    and depends on the optional steganographer + Pillow toolchain.
    """
    if channel_id == StegMediaChannel.id:
        return StegMediaChannel(**kwargs)
    factory = _PURE_CHANNELS.get(channel_id) or _ODT_ONLY_CHANNELS.get(channel_id)
    if factory is None:
        raise ValueError(f"unknown channel: {channel_id}")
    return factory(**kwargs)


def available_channels(include_media: bool = True) -> list[str]:
    """List registered channel ids."""
    ids = list(_PURE_CHANNELS)
    if include_media:
        ids.append(StegMediaChannel.id)
    return ids


__all__ = [
    "Channel",
    "ChannelRecord",
    "CustomXmlChannel",
    "MceChannel",
    "MetadataChannel",
    "OdtMetadataChannel",
    "PackagePartChannel",
    "StegMediaChannel",
    "available_channels",
    "get_channel",
]
