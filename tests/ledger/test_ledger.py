import pytest
import time
import re
from concurrent.futures import ThreadPoolExecutor

from service_node_network import coins, vprint
from ledgerapi import LedgerAPI

executor = ThreadPoolExecutor(max_workers=1)


def test_init(net, mike, hal, ledger):
    """
    Tests that the node fakenet got initialized properly, and that the wallet starts up and shows
    the right address.
    """

    # All nodes should be at the same height:
    heights = [x.rpc("/get_height").json()["height"] for x in net.all_nodes]
    height = max(heights)
    assert heights == [height] * len(net.all_nodes)

    assert mike.height(refresh=True) == height
    assert mike.balances() > (0, 0)
    assert hal.height(refresh=True) == height
    assert hal.balances() == (0, 0)

    address = hal.address()

    text = ledger.curr()
    assert text[0] == "OXEN wallet"
    m = re.search(r"^(\w+)\.\.(\w+)$", text[1])
    assert m
    assert address.startswith(m[1])
    assert address.endswith(m[2])

    # Hit "both" on the address overview to see the full address
    ledger.both()
    assert ledger.curr() == ["Regular address", "(fakenet)"]
    ledger.right()
    assert ledger.read_multi_value("Address") == address


def test_receive(net, mike, hal):
    mike.transfer(hal, coins(100))
    net.mine(blocks=2)
    assert hal.balances(refresh=True) == coins(100, 0)
    net.mine(blocks=7)
    assert hal.balances(refresh=True) == coins(100, 0)
    net.mine(blocks=1)
    assert hal.balances(refresh=True) == coins(100, 100)


def test_send(net, mike, alice, hal, ledger):
    mike.transfer(hal, coins(100))
    net.mine()
    hal.refresh()

    def do_transfer():
        hal.transfer(alice, coins(42.5))

    future = executor.submit(do_transfer)

    time.sleep(1)
    assert ledger.curr() == ["Processing TX"]

    timeout_at = time.time() + 30
    while time.time() < timeout_at:
        text = ledger.curr()
        if text[0] != "Confirm Fee":
            time.sleep(0.5)
            continue

        fee = re.search(r"^(0.01\d{1,7})$", text[1])
        assert fee
        fee = float(fee[1])
        ledger.right()
        assert ledger.curr() == ["Accept"]
        ledger.right()
        assert ledger.curr() == ["Reject"]
        ledger.left()
        ledger.both()
        break
    else:
        assert not "Timeout waiting for transaction on device"

    while time.time() < timeout_at:
        text = ledger.curr()
        if text[0] != "Confirm Amount":
            time.sleep(0.5)
            continue

        assert text[1] == "42.5"
        ledger.right()
        assert ledger.read_multi_value("Recipient") == alice.address()
        ledger.right()
        assert ledger.curr() == ["Accept"]
        ledger.right()
        assert ledger.curr() == ["Reject"]
        ledger.right()
        assert ledger.curr() == ["Confirm Amount", "42.5"]
        ledger.left()
        ledger.left()
        assert ledger.curr() == ["Accept"]
        ledger.both()

    future.result(max(1, timeout_at - time.time()))

    net.mine()
    assert hal.balances(refresh=True) == coins((100 - 42.5 - fee,) * 2)
    assert alice.balances(refresh=True) == coins(42.5, 42.5)
