"""Wait until local server responds (used by start.bat)."""
import sys
import time
import urllib.error
import urllib.request

URL = "http://127.0.0.1:5000/"
TRIES = 40
DELAY = 0.2
TIMEOUT = 0.4


def main() -> int:
    for _ in range(TRIES):
        try:
            urllib.request.urlopen(URL, timeout=TIMEOUT)
            return 0
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(DELAY)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
