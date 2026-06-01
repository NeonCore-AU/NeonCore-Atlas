#!/usr/bin/env python3
"""Generate expanded pseudolocalized text for simple resource files."""
from __future__ import annotations

ACCENTS = str.maketrans({
    "a": "á", "b": "β", "c": "ç", "d": "ð", "e": "é", "f": "ƒ", "g": "ĝ", "h": "h", "i": "î", "j": "ĵ", "k": "ķ", "l": "ļ", "m": "ɱ", "n": "ñ", "o": "õ", "p": "þ", "q": "զ", "r": "ŕ", "s": "š", "t": "ţ", "u": "û", "v": "ṽ", "w": "ŵ", "x": "ҳ", "y": "ý", "z": "ž",
    "A": "Á", "B": "ß", "C": "Ç", "D": "Ð", "E": "É", "F": "Ƒ", "G": "Ĝ", "H": "Ħ", "I": "Î", "J": "Ĵ", "K": "Ķ", "L": "Ļ", "M": "Ṁ", "N": "Ñ", "O": "Õ", "P": "Þ", "Q": "Ǫ", "R": "Ŕ", "S": "Š", "T": "Ţ", "U": "Û", "V": "Ṽ", "W": "Ŵ", "X": "Ҳ", "Y": "Ý", "Z": "Ž",
})

def pseudo(value: str) -> str:
    return "[" + value.translate(ACCENTS) + "~~~~]"

if __name__ == "__main__":
    for sample in ["Connect", "Disconnected", "Import subscription"]:
        print(f"{sample} -> {pseudo(sample)}")
