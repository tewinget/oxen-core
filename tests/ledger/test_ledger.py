import pytest
import time
import re

from service_node_network import coins, vprint
from ledgerapi import LedgerAPI
from expected import *


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

    def check_addr(_, m):
        assert address.startswith(m[1][1]) and address.endswith(m[1][2])

    check_interactions(
        ledger,
        MatchScreen([r"^OXEN wallet$", r"^(\w+)\.\.(\w+)$"], check_addr),
        Do.both,  # Hitting both on the main screen shows us the full address details
        ExactScreen(["Regular address", "(fakenet)"]),
        Do.right,
        MatchMulti("Address", address),
    )


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

    fee = None

    def store_fee(_, m):
        nonlocal fee
        fee = float(m[1][1])

    run_with_interactions(
        ledger,
        lambda: hal.transfer(alice, coins(42.5)),
        ExactScreen(["Processing TX"]),
        MatchScreen([r"^Confirm Fee$", r"^(0.01\d{1,7})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.left,
        Do.both,
        ExactScreen(["Confirm Amount", "42.5"], fail_index=1),
        Do.right,
        MatchMulti("Recipient", alice.address()),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.right,  # This loops back around to the amount:
        ExactScreen(["Confirm Amount", "42.5"]),
        Do.left,
        Do.left,
        ExactScreen(["Accept"]),
        Do.both,
    )

    net.mine(1)
    remaining = coins(100 - 42.5 - fee)
    hal_bal = hal.balances(refresh=True)
    assert hal_bal[0] == remaining
    assert hal_bal[1] < remaining
    assert alice.balances(refresh=True) == coins(42.5, 0)
    net.mine(9)
    assert hal.balances(refresh=True) == (remaining, remaining)
    assert alice.balances(refresh=True) == coins(42.5, 42.5)


def test_multisend(net, mike, alice, bob, hal, ledger):
    mike.transfer(hal, coins(105))
    net.mine()

    assert hal.balances(refresh=True) == coins(105, 105)

    fee = None

    def store_fee(_, m):
        nonlocal fee
        fee = float(m[1][1])

    recipient_addrs = []
    def store_addr(val):
        nonlocal recipient_addrs
        recipient_addrs.append(val)
        print(f"recipient addr: {val}")

    recipient_amounts = []
    def store_amount(_, m):
        nonlocal recipient_addrs
        recipient_amounts.append(m[1][1])
        print(f"recipient amount: {m[1][1]}")

    recipient_expected = [(alice.address(), "18.0"),
                          (bob.address(), "19.0"),
                          (alice.address(), "20.0"),
                          (alice.address(), "21.0"),
                          (hal.address(), "22.0")]

    hal.timeout = 120 # creating this tx with the ledger takes ages
    run_with_interactions(
        ledger,
        lambda: hal.multi_transfer((alice, bob, alice, alice, hal), coins(18, 19, 20, 21, 22)),
        ExactScreen(["Processing TX"]),
        MatchScreen([r"^Confirm Fee$", r"^(0.\d{1,9})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        MatchScreen(["Confirm Amount", r"^(\d{2}.0)$"], store_amount, fail_index=1),
        Do.right,
        MatchMulti("Recipient", None, callback=store_addr),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        MatchScreen(["Confirm Amount", r"^(\d{2}.0)$"], store_amount, fail_index=1),
        Do.right,
        MatchMulti("Recipient", None, callback=store_addr),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        MatchScreen(["Confirm Amount", r"^(\d{2}.0)$"], store_amount, fail_index=1),
        Do.right,
        MatchMulti("Recipient", None, callback=store_addr),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        MatchScreen(["Confirm Amount", r"^(\d{2}.0)$"], store_amount, fail_index=1),
        Do.right,
        MatchMulti("Recipient", None, callback=store_addr),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        MatchScreen(["Confirm Amount", r"^(\d{2}.0)$"], store_amount, fail_index=1),
        Do.right,
        MatchMulti("Recipient", None, callback=store_addr),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        timeout=120,
    )

    recipient_expected.sort()

    recipient_got = list(zip(recipient_addrs, recipient_amounts))
    recipient_got.sort()

    assert recipient_expected == recipient_got

    net.mine(1)
    remaining = coins(105 - 100 - fee + 22)
    hal_bal = hal.balances(refresh=True)
    assert hal_bal[0] == remaining
    assert hal_bal[1] < remaining
    assert alice.balances(refresh=True) == coins(18 + 20 + 21, 0)
    assert bob.balances(refresh=True) == coins(19, 0)
    net.mine(9)
    assert hal.balances(refresh=True) == tuple([remaining] * 2)
    assert alice.balances(refresh=True) == tuple(coins([18 + 20 + 21] * 2))
    assert bob.balances(refresh=True) == coins(19, 19)
