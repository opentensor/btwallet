import urllib.request
from .words import english


def _get_bip39_words_list():
    """Trys to get an actual list of words or uses saved one."""
    try:
        url = (
            "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
        )
        words = urllib.request.urlopen(url).read().decode().splitlines()
        assert len(words) == 2048
        return words
    except Exception:
        return english


def bip39_validate(words: str) -> bool:
    bip39_words_list = _get_bip39_words_list()
    return all([m in bip39_words_list for m in words.split(" ")])
