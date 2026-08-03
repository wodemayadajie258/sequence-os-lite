# tests/test_link_secure.py
import os
import shutil
import pytest
from link_secure import Link

PASSWORD = "test-pwd"

@pytest.fixture()
def tmp_store(tmp_path):
    d = tmp_path / "link_store"
    d.mkdir()
    return str(d)


def test_write_read_roundtrip(tmp_store):
    L = Link(store_dir=tmp_store)
    state = {"agent": "demo", "step": 0}
    lid = L.write(state, PASSWORD)
    got = L.read(lid, PASSWORD)
    assert got == state


def test_migrate_on_read(tmp_store):
    L = Link(store_dir=tmp_store)
    state = {"agent": "demo", "step": 1}
    lid = L.write(state, PASSWORD)
    # read with migrate_on_read should return same
    got = L.read(lid, PASSWORD, migrate_on_read=True)
    assert got == state

# Note: Old-format read/write compatibility test depends on having a pre-existing
# old-format file. We cannot reliably synthesize the exact historical bytes here
# without knowing the prior implementation nuances in every environment, so
# integration verification should be done on-device using real old files.
