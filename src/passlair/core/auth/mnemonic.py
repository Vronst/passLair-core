"""
Renders a backup KEK as a human-writable recovery phrase, and parses it back.

Thin wrapper around the `mnemonic` package (the BIP-39 reference
implementation, https://pypi.org/project/mnemonic/), since it's a well-tested,
standardized way to turn fixed-size key material into something a person can
legibly write on paper and type back in. This module only borrows the
encoding scheme - there's no wallet/blockchain code involved.
"""

from mnemonic import Mnemonic

KEK_SIZE = 32
WORD_COUNT = 24

_mnemonic = Mnemonic("english")


def kek_to_phrase(kek: bytes) -> str:
    """Encodes a 32-byte backup KEK as a 24-word BIP-39 recovery phrase."""
    if len(kek) != KEK_SIZE:
        raise ValueError("Backup KEK must be 32 bytes.")

    return _mnemonic.to_mnemonic(kek)


def phrase_to_kek(phrase: str) -> bytes:
    """Parses a recovery phrase back into the 32-byte backup KEK it encodes.

    Raises ValueError if the phrase is malformed, uses unknown words, or
    fails its checksum (e.g. a mistyped/mistranscribed word).
    """
    if len(phrase.split()) != WORD_COUNT:
        raise ValueError(f"Backup phrase must have {WORD_COUNT} words.")

    if not _mnemonic.check(phrase):
        raise ValueError("Backup phrase failed its checksum - check for typos.")

    return bytes(_mnemonic.to_entropy(phrase))
