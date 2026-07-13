"""Verify a Veriform TDX quote on-chain via Automata's DCAP attestation — for
free. `verifyAndAttestOnChain` can be simulated with eth_call, so this needs no
wallet, no gas, and no testnet tokens: a public RPC returns whether the EVM,
using Automata's on-chain Intel PCCS collateral, accepts the quote.

    python scripts/automata_verify.py [quote.hex]

Defaults to docs/phase3-real-quote.hex, then tests/fixtures/real_tdx_quote.hex.

Optional real transaction (records the attestation on-chain): set VERIFORM_SEND=1
and PRIVATE_KEY=<funded testnet key>. Left off by default — the free eth_call
already proves acceptance.

Networks (override with AUTOMATA_RPC / AUTOMATA_ADDR):
    Ethereum Sepolia  0x63eF330eAaadA189861144FCbc9176dae41A5BAf   (default)
    Automata testnet  0xd3A3f34E8615065704cCb5c304C0cEd41bB81483
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_RPC = os.getenv("AUTOMATA_RPC", "https://ethereum-sepolia-rpc.publicnode.com")
DEFAULT_ADDR = os.getenv("AUTOMATA_ADDR", "0x63eF330eAaadA189861144FCbc9176dae41A5BAf")

ABI = [{
    "type": "function",
    "name": "verifyAndAttestOnChain",
    "stateMutability": "nonpayable",
    "inputs": [{"name": "rawQuote", "type": "bytes"}],
    "outputs": [{"name": "success", "type": "bool"},
                {"name": "output", "type": "bytes"}],
}]


def _load_quote(argv) -> bytes:
    candidates = []
    if len(argv) > 1:
        candidates.append(Path(argv[1]))
    candidates += [ROOT / "docs" / "phase3-real-quote.hex",
                   ROOT / "tests" / "fixtures" / "real_tdx_quote.hex"]
    for p in candidates:
        if p.exists():
            print(f"==> Quote: {p}")
            return bytes.fromhex(p.read_text().strip().removeprefix("0x"))
    sys.exit(f"no quote file found (looked in: {', '.join(str(c) for c in candidates)})")


def main() -> int:
    try:  # keep emoji output from crashing on cp1252 (Windows) consoles
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    try:
        from web3 import Web3
    except ImportError:
        sys.exit("web3 is required: pip install web3")

    quote = _load_quote(sys.argv)
    print(f"    {len(quote)} bytes")

    w3 = Web3(Web3.HTTPProvider(DEFAULT_RPC))
    if not w3.is_connected():
        sys.exit(f"could not reach RPC {DEFAULT_RPC}")
    print(f"==> DCAP verifier {DEFAULT_ADDR} on {DEFAULT_RPC}")

    dcap = w3.eth.contract(address=Web3.to_checksum_address(DEFAULT_ADDR), abi=ABI)

    # Free path: eth_call simulates the verification, no gas, no wallet.
    print("==> eth_call verifyAndAttestOnChain (gasless simulation)…")
    try:
        success, output = dcap.functions.verifyAndAttestOnChain(quote).call()
    except Exception as exc:
        # A revert here almost always means the on-chain PCCS on this network
        # has no collateral for THIS quote's platform (FMSPC) yet — not that the
        # quote is invalid. Upsert the collateral first (Automata's PCCS DAO, or
        # the tdx-attestation-sdk flow), or use a network where it's present.
        print(f"\n⚠  verifyAndAttestOnChain reverted: {exc}")
        print("   Most likely cause: this quote's platform collateral (FMSPC "
              "TCB info / PCK CRL) is not yet in the on-chain PCCS on this "
              "network. Register it via Automata's on-chain PCCS, then re-run. "
              "The offline check (scripts/tdx-quote.sh / dcap.py) does not need "
              "this — it carries its own Intel collateral in the quote.")
        return 1

    print(f"\n    success = {success}")
    print(f"    output  = {len(output)} bytes")
    if success:
        print("\n✅ Automata's on-chain DCAP verifier ACCEPTS this quote — the full "
              "Intel chain of trust checks out in the EVM, against on-chain PCCS "
              "collateral. This is the same guarantee our dcap.py proves offline, "
              "now enforceable by any smart contract.")
    else:
        print("\n❌ On-chain verifier rejected the quote (returned success=false).")

    if os.getenv("VERIFORM_SEND") == "1" and os.getenv("PRIVATE_KEY"):
        _send_tx(w3, dcap, quote)

    return 0 if success else 1


def _send_tx(w3, dcap, quote):
    """Record the attestation on-chain for real (needs a funded testnet key)."""
    acct = w3.eth.account.from_key(os.environ["PRIVATE_KEY"])
    print(f"\n==> Sending real tx from {acct.address}…")
    tx = dcap.functions.verifyAndAttestOnChain(quote).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
    })
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"    tx: {h.hex()} — waiting for receipt…")
    rcpt = w3.eth.wait_for_transaction_receipt(h)
    print(f"    mined in block {rcpt.blockNumber}, status={rcpt.status}")


if __name__ == "__main__":
    raise SystemExit(main())
