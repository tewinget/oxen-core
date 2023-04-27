import pytest
import time

from service_node_network import coins, vprint


def test_init(net, mike, hal):
    """Tests that the service node test network got initialized properly.  (This isn't really a test
    so much as it is a verification that the test code is working as it is supposed to)."""

    # All nodes should be at the same height:
    heights = [x.rpc("/get_height").json()["height"] for x in net.all_nodes]
    height = max(heights)
    assert heights == [height] * len(net.all_nodes)

    assert mike.height(refresh=True) == height
    assert mike.balances() > (0, 0)
    assert hal.height(refresh=True) == height
    assert hal.balances() == (0, 0)


def test_receive(net, mike, hal):
    mike.transfer(hal, coins(100))
    net.mine()
    assert hal.balances(refresh=True) == coins(100, 100)
