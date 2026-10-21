import os

import pytest

from threatlens.core import db
from threatlens.core.config import Settings


def test_ttl_indexes_bound_storage():
    """Atlas M0 is 512 MB: raw events and content snapshots must expire."""

    def ttl(collection):
        return [i.document.get("expireAfterSeconds") for i in db.INDEXES[collection] if "expireAfterSeconds" in i.document]

    assert ttl(db.C.events) == [7 * db.DAY]
    assert ttl(db.C.content_items) == [30 * db.DAY]
    assert ttl(db.C.revoked_tokens) == [0]


@pytest.mark.skipif(not os.getenv("MONGO_TEST_URI"), reason="set MONGO_TEST_URI (e.g. an Atlas test database) to run")
async def test_indexes_apply_against_a_real_database():
    s = Settings(env="test", mongo_uri=os.environ["MONGO_TEST_URI"], mongo_db="threatlens_test")
    database = db.connect(s)
    try:
        assert await db.ping(database)
        await db.ensure_indexes(database)
        names = await database[db.C.events].index_information()
        assert "ttl_ts" in names
    finally:
        await db.close()
