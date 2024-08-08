#!/usr/bin/python3

# Generates one of the src/sent_transition/{mainnet,devnet,testnet}.cpp files from a postgresql
# database containing aggregate shares (i.e. as stored by the swap.oxen.io backend).

import argparse
import psycopg
import string
import sys

parser = argparse.ArgumentParser(
    prog="generate",
    description="Generates mainnet, devnet, or testnet transition values from a postgresql database",
)

parser.add_argument(
    "db",
    help='postgresql connection URI, such as "postgresql:///dbname" to the database with the aggregate_shares_registered and sn_pk_updates tables/views',
)

net_group = parser.add_argument_group(
    "Network type", "The network (mainnet, devnet, or testnet) being generated"
).add_mutually_exclusive_group(required=True)
net_group.add_argument(
    "-m", "--mainnet", action="store_true", help="generate mainnet transition data"
)
net_group.add_argument(
    "-t", "--testnet", action="store_true", help="generate testnet transition data"
)
net_group.add_argument(
    "-d", "--devnet", action="store_true", help="generate devnet transition data"
)

parser.add_argument(
    "-o",
    "--out",
    help="output filename, or - for stdout; if omitted will be mainnet.cpp, testnet.cpp, or devnet.cpp in the current directory",
)
parser.add_argument(
    "-f",
    "--force",
    action="store_true",
    help="force overwriting the output file if it already exists",
)
parser.add_argument(
    "-r",
    "--ratio",
    nargs=2,
    required=True,
    type=int,
    help="OXEN -> SENT conversion ratio, as a pair of integers.  For example, --ratio 2 3 means 3000 staked OXEN converts to 2000 SENT (before any bonus is added)",
)
parser.add_argument(
    "-b",
    "--bonus",
    type=float,
    help="The total value of the SENT bonus. The default is 30M for mainnet; the value must be specified for devnet/testnet",
)

args = parser.parse_args()

# if sum((args.mainnet, args.testnet, args.devnet)) != 1:
#    parser.error("exactly one of --mainnet, --testnet, --devnet must be given")

bonus_total = args.bonus
if bonus_total is None:
    if args.mainnet:
        bonus_total = 30_000_000
    else:
        parser.error("--bonus must be given for --devnet/--testnet generation")

if len(args.ratio) != 2 or any(not 1 <= x <= 255 for x in args.ratio):
    parser.error("Invalid --ratio: ratio arguments must be in [1, 255]")

if not (args.db.startswith("postgres://") or args.db.startswith("postgresql://")):
    parser.error(
        "invalid postgresql URI: see https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING for connection URI syntax"
    )

oxen_sent = {}  # oxen address => sent address
sent_shares = (
    {}
)  # sent address => total shares (across all OXEN wallets mapping to that sent address)

# SN primary pubkey => (ed25519 pubkey, BLS pubkey), all in hex
# The ed25519 pubkey will *become* the primary pubkey at the hard fork, if different (i.e. only for
# pre-Oxen 8 SNs; new installs since Oxen 8 have matching keys).
sn_pubkeys = {}


def is_hex_pk(s: str, keysize: int = 32):
    return len(s) == 2 * keysize and all(c in string.hexdigits for c in s)


with psycopg.connect(args.db) as conn:
    with conn.cursor() as cur:
        cur.execute(
            "select address, destination, shares from aggregate_shares_registered"
        )
        for addr, dest, shares in cur:
            if not shares > 0:
                continue
            assert addr not in oxen_sent
            oxen_sent[addr] = dest
            sent_shares.setdefault(dest, 0.0)
            sent_shares[dest] += shares

        cur.execute("select old_primary_pk, pk_ed25519, pk_bls FROM sn_pk_updates")
        for primary, ed, bls in cur:
            if not is_hex_pk(primary):
                raise RuntimeError(
                    f"Invalid data in sn_pk_updates: snode {primary} pk is not 64 hex digits"
                )
            if not is_hex(ed):
                raise RuntimeError(
                    f"Invalid data in sn_pk_updates: snode {primary} ed25519 pubkey is not 64 hex digits"
                )
            if not is_hex_pk(bls, 64):
                raise RuntimeError(
                    f"Invalid data in sn_pk_updates: snode {primary} BLS pubkey is not 128 hex digits"
                )

            sn_pubkeys[primary] = (ed, bls)


net_name = "mainnet" if args.mainnet else "testnet" if args.testnet else "devnet"

if args.out is None:
    args.out = f"{net_name}.cpp"

if args.out == "-":
    out = sys.stdout
elif args.force:
    out = open(args.out, "w")
else:
    try:
        out = open(args.out, "x")
    except FileExistsError:
        parser.error(
            f"{args.out} already exists; use --force/-f to overwrite, or specify a different filename"
        )

print(
    f"""

// DO NOT DIRECTLY EDIT THIS FILE!
// This file is generated by generate.py based on SENT transition data.

#include <cstdint>
#include <string>
#include <unordered_map>

namespace oxen::sent::{net_name} {{

using namespace std::literals;

const std::unordered_map<std::string, std::string> addresses{{
""",
    file=out,
)

for oxen, sent in sorted(oxen_sent.items()):
    print(f'        {{"{oxen}"s,\n         "{sent}"s}},', file=out)

print(
    f"""
}};  // {len(oxen_sent)} registered addresses

const std::pair<std::uint8_t, std::uint8_t> conv_ratio{{{args.ratio[0]}, {args.ratio[1]}}};

const std::unordered_map<std::string, std::uint64_t> transition_bonus{{
""",
    file=out,
)

total_shares = sum(sent_shares.values())
actual_bonus_total = 0.0

for sent, shares in sorted(sent_shares.items()):
    bonus = int(shares / total_shares * bonus_total * 1e9)
    print(f'        {{"{sent}"s, {bonus}}},', file=out)
    actual_bonus_total += bonus


print(
    f"""
}};  // Actual bonus total: {actual_bonus_total*1e-9:.9f} of target {bonus_total:.9f}


const std::unordered_map<std::string, std::pair<std::string, std::string>> sent_pubkeys{{
""",
    file=out,
)

for primary, (ed, bls) in sorted(sn_pubkeys.items()):
    print(f'        {{"{primary}"s, {{"{ed}"s, "{bls}"s}}}},', file=out)

print(
    f"""
}}; // {len(sn_pubkeys)} service node pubkeys

}}  // namespace oxen::sent::{net_name}
""",
    file=out,
    end="",
)