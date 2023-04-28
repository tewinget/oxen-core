import requests
import urllib.parse
import time
import re


class SingleBaseSession(requests.Session):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url

    def request(self, method, url, *args, **kwargs):
        return super().request(method, urllib.parse.urljoin(self.base_url, url), *args, **kwargs)


class LedgerAPI:
    def __init__(self, api_url):
        self.api = SingleBaseSession(api_url)

        # Don't care what this returns, just make sure it works to test availability:
        self.curr()

    def curr(self):
        """Returns the text of events on the current screen"""
        return [e["text"] for e in self.api.get("/events?currentscreenonly=true").json()["events"]]

    def _touch(self, which, action, delay, sleep):
        json = {"action": action}
        if delay:
            json["delay"] = delay
        self.api.post(f"/button/{which}", json=json)
        if sleep:
            time.sleep(sleep)

    def left(self, *, sleep=0.1, action="press-and-release", delay=None):
        """Hit the left button; sleeps for `sleep` seconds after pushing to wait for it to register"""
        self._touch("left", action, delay, sleep)

    def right(self, *, sleep=0.1, action="press-and-release", delay=None):
        """Hit the right button; sleeps for `sleep` seconds after pushing to wait for it to register"""
        self._touch("right", action, delay, sleep)

    def both(self, *, sleep=0.1, action="press-and-release", delay=None):
        """Hit both buttons simultaneously; sleeps for `sleep` seconds after pushing to wait for it to register"""
        self._touch("both", action, delay, sleep)

    def read_multi_value(self, title):
        """Feed this the ledger on the first "{title} (1/N)" screen and it will read through, collect
        the multi-part value, and return it.  Throws assert failures if there aren't screens 1/N through
        N/N.  Leaves it on the N/N screen."""

        text = self.curr()
        disp_n = re.search("^" + re.escape(title) + r" \(1/(\d+)\)$", text[0])
        assert disp_n
        disp_n = int(disp_n[1])
        full_value = text[1]
        i = 1
        while i < disp_n:
            self.right()
            i += 1
            text = self.curr()
            assert text[0] == f"{title} ({i}/{disp_n})"
            full_value += text[1]

        return full_value


