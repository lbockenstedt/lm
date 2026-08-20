"""Unit tests for ``henet_scrape`` — the read-only dns.he.net web-panel scraper.

The scraper logs into the HE web panel and enumerates a zone's existing records
so records added directly at HE (invisible to the push-only dyndns API) can be
brought under management. Every test injects a fake ``fetch`` so nothing touches
the network; the fixture HTML mirrors the real dns.he.net panel structure
(login form, ``img[alt=delete]`` zone rows, and ``tr.dns_tr`` record rows with an
``rrlabel`` type span and a ``data=`` value cell — including a commented-out td
and non-A/AAAA rows the importer must skip).
"""

import henet_scrape


_LOGIN_PAGE = '<form><input type="text" name="email" /><input type="password" name="pass"/></form>'

_ACCOUNT_PAGE = (
    '<div>Account Menu … <a href="/?action=logout">Logout</a></div>'
    '<table><tbody>'
    '<tr><td><img class="Tips" alt="delete" onclick="delete_dom(this);" '
    'name="example.com" value="784067" src="/include/images/delete.png" /></td></tr>'
    '</tbody></table>'
)

# One zone's edit page: a locked SOA row, an A, a dynamic AAAA, plus MX/TXT that
# must be skipped (HE dyndns manages A/AAAA only). Mirrors the real markup: hidden
# id cells, a commented-out image td, an rrlabel span carrying data="TYPE", and a
# value td whose full value is in a data= attribute.
def _rec_row(rid, name, rtype, ttl, value, dynamic="0", cls="dns_tr"):
    return (
        f'<tr class="{cls}" id="{rid}" onclick="editRow(this)">'
        '<td class="hidden">784067</td>'
        f'<td class="hidden">{rid}</td>'
        f'<td width="95%" class="dns_view">{name}</td>'
        '<!-- <td align="center"><img src="/x.gif" data="X" alt="X"/></td> -->'
        f'<td align="center"><span class="rrlabel {rtype}" data="{rtype}" alt="{rtype}">{rtype}</span></td>'
        f'<td align="left">{ttl}</td>'
        '<td align="center">-</td>'
        f'<td align="left" data="{value}">{value}</td>'
        f'<td class="hidden">{dynamic}</td>'
        '<td></td>'
        '<td class="dns_delete"><img src="/include/images/delete.png" alt="delete"/></td>'
        '</tr>'
    )


_EDIT_ZONE = (
    '<table id="dns_main_content"><tbody>'
    + _rec_row("1", "example.com", "SOA", "86400", "ns1.he.net", cls="dns_tr_locked")
    + _rec_row("2", "www.example.com", "A", "300", "203.0.113.10")
    + _rec_row("3", "home.example.com", "AAAA", "600", "2001:db8::1", dynamic="1", cls="dns_tr_dynamic")
    + _rec_row("4", "example.com", "MX", "3600", "10 mail.example.com")
    + _rec_row("5", "_acme.example.com", "TXT", "300", "sometoken")
    + '</tbody></table>'
)


class _FakeFetch:
    """Route (method, url) → (status, body). Records posts for assertion."""

    def __init__(self, login_ok=True):
        self.login_ok = login_ok
        self.posts = []

    def __call__(self, method, url, data=None):
        if method == "POST":
            self.posts.append((url, data))
            return 200, (_ACCOUNT_PAGE if self.login_ok else _LOGIN_PAGE)
        # GET
        if "menu=edit_zone" in url:
            return 200, _EDIT_ZONE
        # account home (after login) vs the initial cookie-seed GET
        return 200, _ACCOUNT_PAGE


def test_import_all_returns_only_a_aaaa_and_tallies_skipped():
    fetch = _FakeFetch(login_ok=True)
    s = henet_scrape.HENetScraper(fetch=fetch)
    res = s.import_all("me@example.com", "secret")
    assert res["status"] == "SUCCESS", res
    names = {(r["name"], r["type"]) for r in res["records"]}
    assert names == {("www.example.com", "A"), ("home.example.com", "AAAA")}
    # value + ttl + dynamic flag parsed off the real cell layout
    aaaa = next(r for r in res["records"] if r["type"] == "AAAA")
    assert aaaa["value"] == "2001:db8::1"
    assert aaaa["ttl"] == 600
    assert aaaa["is_dynamic"] is True
    assert aaaa["zone"] == "example.com"
    # MX + TXT + SOA are not manageable → surfaced as skipped counts
    assert res["skipped_types"] == {"SOA": 1, "MX": 1, "TXT": 1}
    # the login POST carried the account creds in HE's field names
    assert fetch.posts and fetch.posts[0][1] == {"email": "me@example.com", "pass": "secret"}


def test_import_all_login_failure_is_error():
    s = henet_scrape.HENetScraper(fetch=_FakeFetch(login_ok=False))
    res = s.import_all("me@example.com", "wrong")
    assert res["status"] == "ERROR"
    assert "login failed" in res["message"].lower()


def test_import_all_requires_credentials():
    s = henet_scrape.HENetScraper(fetch=_FakeFetch())
    res = s.import_all("", "")
    assert res["status"] == "ERROR"
    assert "required" in res["message"].lower()


def test_zone_filter_selects_one_zone():
    s = henet_scrape.HENetScraper(fetch=_FakeFetch())
    ok = s.import_all("me@example.com", "secret", zone_filter="example.com")
    assert ok["status"] == "SUCCESS" and ok["zones"][0]["name"] == "example.com"
    miss = s.import_all("me@example.com", "secret", zone_filter="nope.com")
    assert miss["status"] == "ERROR" and "no matching" in miss["message"].lower()


def test_list_zones_parses_domain_and_id():
    s = henet_scrape.HENetScraper(fetch=_FakeFetch())
    s.login("me@example.com", "secret")
    zones = s.list_zones()
    assert zones == [{"name": "example.com", "zone_id": "784067"}]


def test_find_zone_for_picks_longest_matching_zone():
    zones = [{"name": "example.com", "zone_id": "1"},
             {"name": "sub.example.com", "zone_id": "2"}]
    assert henet_scrape._find_zone_for("a.b.example.com", zones)["zone_id"] == "1"
    # a record inside the more-specific hosted zone prefers that zone
    assert henet_scrape._find_zone_for("x.sub.example.com", zones)["zone_id"] == "2"
    assert henet_scrape._find_zone_for("sub.example.com", zones)["zone_id"] == "2"
    assert henet_scrape._find_zone_for("other.net", zones) is None


class _StatefulFetch:
    """A fake HE panel that actually applies create/update POSTs, so a write is
    reflected in the next edit-zone read (as the real verify step relies on)."""

    def __init__(self, login_ok=True):
        self.login_ok = login_ok
        self.posts = []
        self._next_id = 100
        # (name, type) -> dict(id,name,type,ttl,value,dynamic)
        self.state = {
            ("www.example.com", "A"): dict(id="2", name="www.example.com", type="A",
                                           ttl="300", value="203.0.113.10", dynamic="0"),
        }

    def _zone_html(self):
        rows = "".join(_rec_row(r["id"], r["name"], r["type"], r["ttl"], r["value"], r["dynamic"])
                       for r in self.state.values())
        return f'<table id="dns_main_content"><tbody>{rows}</tbody></table>'

    def __call__(self, method, url, data=None):
        if method == "POST":
            self.posts.append((url, data))
            if data and data.get("hosted_dns_editrecord") in ("Submit", "Update"):
                key = (data["Name"].rstrip("."), data["Type"].upper())
                rid = data.get("hosted_dns_recordid") or str(self._next_id)
                if not data.get("hosted_dns_recordid"):
                    self._next_id += 1
                self.state[key] = dict(id=rid, name=key[0], type=key[1],
                                       ttl=str(data.get("TTL", "300")),
                                       value=data.get("Content", ""), dynamic="0")
                return 200, '<div id="dns_status">updated</div>'
            return 200, (_ACCOUNT_PAGE if self.login_ok else _LOGIN_PAGE)
        if "menu=edit_zone" in url:
            return 200, self._zone_html()
        return 200, _ACCOUNT_PAGE


def test_set_records_creates_new_record():
    fetch = _StatefulFetch()
    s = henet_scrape.HENetScraper(fetch=fetch)
    res = s.set_records("me@example.com", "secret",
                        [{"name": "new.example.com", "type": "A", "value": "198.51.100.7", "ttl": 120}])
    assert res["status"] == "SUCCESS", res
    assert res["results"][0]["ok"] is True
    # create → empty record id + Submit, carrying the account-login session
    write = next(p for p in fetch.posts if isinstance(p[1], dict) and p[1].get("Name") == "new.example.com")
    assert write[1]["hosted_dns_editrecord"] == "Submit"
    assert write[1]["hosted_dns_recordid"] == ""
    assert write[1]["Content"] == "198.51.100.7" and write[1]["TTL"] == "120"


def test_set_records_updates_existing_in_place():
    fetch = _StatefulFetch()
    s = henet_scrape.HENetScraper(fetch=fetch)
    res = s.set_records("me@example.com", "secret",
                        [{"name": "www.example.com", "type": "A", "value": "203.0.113.99"}])
    assert res["status"] == "SUCCESS", res
    write = next(p for p in fetch.posts if isinstance(p[1], dict) and p[1].get("Name") == "www.example.com")
    # existing record → Update carrying its real record id (2)
    assert write[1]["hosted_dns_editrecord"] == "Update"
    assert write[1]["hosted_dns_recordid"] == "2"


def test_set_records_rejects_non_a_aaaa_and_unknown_zone():
    fetch = _StatefulFetch()
    s = henet_scrape.HENetScraper(fetch=fetch)
    res = s.set_records("me@example.com", "secret", [
        {"name": "mail.example.com", "type": "MX", "value": "10 mx.example.com"},
        {"name": "host.other.net", "type": "A", "value": "1.2.3.4"},
    ])
    assert res["status"] == "ERROR"  # nothing applied
    details = {r["name"]: r["detail"] for r in res["results"]}
    assert "A/AAAA" in details["mail.example.com"]
    assert "zone" in details["host.other.net"]


def test_set_records_login_failure_is_error():
    s = henet_scrape.HENetScraper(fetch=_StatefulFetch(login_ok=False))
    res = s.set_records("me@example.com", "wrong",
                        [{"name": "www.example.com", "type": "A", "value": "1.1.1.1"}])
    assert res["status"] == "ERROR" and "login failed" in res["message"].lower()
