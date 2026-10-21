from threatlens.core.bus import EventBus


async def test_publish_reaches_all_subscribers_and_survives_failures():
    bus = EventBus()
    seen: list[str] = []

    async def ok(payload):
        seen.append(payload)

    async def boom(payload):
        raise RuntimeError("subscriber crashed")

    bus.subscribe("t", ok)
    bus.subscribe("t", boom)
    bus.subscribe("t", ok)

    bus.publish("t", "hello")  # returns immediately, never raises
    await bus.drain()

    assert seen == ["hello", "hello"]


async def test_unsubscribe_and_unknown_topic():
    bus = EventBus()
    seen: list[int] = []

    async def h(p):
        seen.append(p)

    unsubscribe = bus.subscribe("t", h)
    bus.publish("t", 1)
    unsubscribe()
    bus.publish("t", 2)
    bus.publish("nobody-listens", 3)
    await bus.drain()

    assert seen == [1]
