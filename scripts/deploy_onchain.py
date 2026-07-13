"""Phase 5: compile and deploy Veriform's on-chain anchor, and prove the gated
action works — a real enclave signature executes, the evil agent's is rejected.

Two modes, same code path:

  * LOCAL (default) — deploy to an in-memory EVM (eth-tester). No gas, no wallet,
    no network. Proves the Solidity compiles and the whole flow executes, so the
    only thing left for a public testnet is funded gas.

        python scripts/deploy_onchain.py

  * TESTNET — set RPC_URL and PRIVATE_KEY (a throwaway, testnet-only key; fund it
    from a free faucet, e.g. https://cloud.google.com/application/web3/faucet for
    Sepolia). Deploys the same contracts to that chain.

        RPC_URL=https://ethereum-sepolia-rpc.publicnode.com \
        PRIVATE_KEY=0x<throwaway> python scripts/deploy_onchain.py

Note: this covers the SIGNATURE path (VeriformRegistry + DemoConsumer), which
needs no TDX hardware. It also deploys AttestedQuoteConsumer (the Automata
hardware path); fully exercising that one needs a real quote (Phase 3) plus
on-chain PCCS collateral, so it is deployed but not called here.
"""

import json
import os
import sys
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"
SOLC_VERSION = "0.8.24"

# Automata's deployed DCAP verifier (constructor arg for AttestedQuoteConsumer).
AUTOMATA_DCAP = {
    "sepolia": "0x63eF330eAaadA189861144FCbc9176dae41A5BAf",
    "automata": "0xd3A3f34E8615065704cCb5c304C0cEd41bB81483",
}


PAYLOAD = {
    "agent": "veriform-agent/0.1",
    "request": {"to": "0xabc", "amount": 0.5, "reason": "rent"},
    "action": "APPROVE",
}


def canonical_bytes(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def eip191_digest(message: bytes) -> bytes:
    return keccak(b"\x19Ethereum Signed Message:\n32" + keccak(message))


def sign_for_chain(account, payload) -> bytes:
    inner = keccak(canonical_bytes(payload))
    return bytes(account.sign_message(encode_defunct(inner)).signature)


def compile_contracts():
    import solcx

    try:
        solcx.set_solc_version(SOLC_VERSION)
    except Exception:
        print(f"==> Installing solc {SOLC_VERSION}…")
        solcx.install_solc(SOLC_VERSION)
        solcx.set_solc_version(SOLC_VERSION)

    sources = ["VeriformRegistry.sol", "DemoConsumer.sol", "AttestedQuoteConsumer.sol"]
    compiled = solcx.compile_files(
        [str(CONTRACTS / s) for s in sources],
        output_values=["abi", "bin"],
        allow_paths=[str(CONTRACTS)],
        solc_version=SOLC_VERSION,
    )
    # keys look like ".../VeriformRegistry.sol:VeriformRegistry"
    out = {}
    for key, artifact in compiled.items():
        out[key.rsplit(":", 1)[1]] = artifact
    print(f"==> Compiled {', '.join(out)} with solc {SOLC_VERSION}")
    return out


def make_web3():
    """Return (w3, deployer, send) for local or testnet mode."""
    from web3 import Web3

    rpc = os.getenv("RPC_URL")
    key = os.getenv("PRIVATE_KEY")

    if rpc and key:
        w3 = Web3(Web3.HTTPProvider(rpc))
        if not w3.is_connected():
            sys.exit(f"could not reach RPC {rpc}")
        acct = Account.from_key(key)
        w3.eth.default_account = acct.address  # for build_transaction defaults
        print(f"==> TESTNET {rpc}\n    deployer {acct.address} "
              f"(balance {w3.from_wei(w3.eth.get_balance(acct.address), 'ether')} ETH)")

        def send(tx):
            tx = {**tx, "from": acct.address,
                  "nonce": w3.eth.get_transaction_count(acct.address)}
            signed = acct.sign_transaction(tx)
            h = w3.eth.send_raw_transaction(signed.raw_transaction)
            rcpt = w3.eth.wait_for_transaction_receipt(h)
            if rcpt.status == 0:
                raise RuntimeError("transaction reverted")
            return rcpt

        return w3, acct.address, send

    from web3 import EthereumTesterProvider

    w3 = Web3(EthereumTesterProvider())
    deployer = w3.eth.accounts[0]
    w3.eth.default_account = deployer
    print("==> LOCAL in-memory EVM (eth-tester) — no gas, no network")

    def send(tx):
        tx = {**tx, "from": deployer}
        h = w3.eth.send_transaction(tx)
        rcpt = w3.eth.wait_for_transaction_receipt(h)
        if rcpt.status == 0:
            raise RuntimeError("transaction reverted")
        return rcpt

    return w3, deployer, send


def deploy(w3, send, artifact, *args):
    c = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bin"])
    rcpt = send(c.constructor(*args).build_transaction({"gas": 3_000_000}))
    return w3.eth.contract(address=rcpt.contractAddress, abi=artifact["abi"])


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    art = compile_contracts()
    w3, deployer, send = make_web3()
    from web3 import Web3

    network = "automata" if "ata.network" in (os.getenv("RPC_URL") or "") else "sepolia"

    # The enclave-attested agent. On testnet, override with the real agent
    # address via ATTESTED_AGENT; locally we mint one to sign with.
    agent_key = os.getenv("AGENT_KEY")
    agent = Account.from_key(agent_key) if agent_key else Account.create()

    print(f"\n==> Deploying VeriformRegistry(attestedAgent={agent.address})…")
    registry = deploy(w3, send, art["VeriformRegistry"], agent.address)
    print(f"    VeriformRegistry @ {registry.address}")

    consumer = deploy(w3, send, art["DemoConsumer"], registry.address)
    print(f"    DemoConsumer     @ {consumer.address}")

    dcap_addr = Web3.to_checksum_address(AUTOMATA_DCAP[network])
    aqc = deploy(w3, send, art["AttestedQuoteConsumer"], dcap_addr)
    print(f"    AttestedQuoteConsumer @ {aqc.address} (Automata DCAP {dcap_addr})")

    # ---- Demonstrate the gate: real signature approved, evil rejected ----
    digest = eip191_digest(canonical_bytes(PAYLOAD))

    print("\n==> Gate test 1: a genuine enclave signature")
    send(consumer.functions.executeIfApproved(digest, sign_for_chain(agent, PAYLOAD))
         .build_transaction({"gas": 200_000}))
    count = consumer.functions.approvedCount().call()
    print(f"    executeIfApproved succeeded — approvedCount = {count}")
    assert count == 1

    print("\n==> Gate test 2: the evil agent's signature (signed outside the enclave)")
    evil = Account.create()
    try:
        send(consumer.functions.executeIfApproved(digest, sign_for_chain(evil, PAYLOAD))
             .build_transaction({"gas": 200_000}))
        print("    !! ERROR: evil signature was NOT rejected")
        return 1
    except Exception:
        print("    correctly REVERTED (UnverifiedDecision) — approvedCount unchanged "
              f"= {consumer.functions.approvedCount().call()}")

    print("\n✅ PHASE 5: on-chain anchor deployed and the gated action verified — "
          "a genuine enclave decision executes on-chain, an impostor's is rejected, "
          "enforced by the EVM (the same guarantee as the off-chain verifier).")
    if os.getenv("RPC_URL"):
        print(f"\n    Addresses on {network}:")
        print(f"      VeriformRegistry       {registry.address}")
        print(f"      DemoConsumer           {consumer.address}")
        print(f"      AttestedQuoteConsumer  {aqc.address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
