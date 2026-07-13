// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Automata's on-chain DCAP attestation entrypoint. Given a raw Intel
///         DCAP quote it fetches the Intel collateral from Automata's on-chain
///         PCCS and verifies the full chain of trust in the EVM, returning
///         success plus a serialized output. Deployed (DCAP v1.0), audited by
///         Trail of Bits:
///           Automata testnet/mainnet: 0xd3A3f34E8615065704cCb5c304C0cEd41bB81483
///           Ethereum Sepolia/mainnet: 0x63eF330eAaadA189861144FCbc9176dae41A5BAf
interface IAutomataDcapAttestation {
    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        returns (bool success, bytes memory output);
}

/// @title AttestedQuoteConsumer
/// @notice The on-chain twin of Veriform's verifier. It executes a guarded
///         action only when BOTH hold:
///           1. the TDX quote is genuine Intel hardware output — proven in the
///              EVM by Automata's DCAP verifier (the same chain of trust our
///              off-chain dcap.py walks), and
///           2. the quote's report_data commits to THIS exact decision and key
///              — recomputed on-chain as sha256(decisionHash || lowercase(addr)),
///              the identical binding the enclave produced (agent/app/enclave.py).
///
/// A genuine enclave passes both. A forged quote fails (1); a real quote reused
/// for a different decision fails (2). No trust in the caller's claims: every
/// input is checked against bytes the hardware signed.
contract AttestedQuoteConsumer {
    IAutomataDcapAttestation public immutable dcap;

    uint256 public attestedCount;

    event ActionExecuted(bytes32 indexed decisionHash, address indexed enclave);

    error QuoteVerificationFailed(bytes output);
    error BindingMismatch(bytes32 want, bytes32 got);
    error QuoteTooShort();

    // report_data is the final 64 bytes of the 584-byte TD report, which begins
    // after the 48-byte header => absolute byte offset 568. Our decision binding
    // is its first 32 bytes; the remaining 32 are zero padding.
    uint256 internal constant REPORT_DATA_OFFSET = 568;

    constructor(IAutomataDcapAttestation _dcap) {
        dcap = _dcap;
    }

    /// @notice The 32-byte decision binding the quote commits to (read straight
    ///         from report_data). Pure mirror of verify.py's REPORT_DATA slice.
    function reportDataBinding(bytes calldata rawQuote) public pure returns (bytes32 out) {
        if (rawQuote.length < REPORT_DATA_OFFSET + 32) revert QuoteTooShort();
        assembly {
            out := calldataload(add(rawQuote.offset, REPORT_DATA_OFFSET))
        }
    }

    /// @notice Recompute the enclave's binding on-chain:
    ///         sha256(decisionHash || ascii-lowercase-hex(enclave)).
    ///         Matches expected_report_data() in agent/app/enclave.py exactly.
    function expectedBinding(bytes32 decisionHash, address enclave)
        public
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(decisionHash, _toLowerHexBytes(enclave)));
    }

    /// @notice Verify a TDX quote on-chain and, if genuine and bound to this
    ///         decision, execute the guarded action. Reverts otherwise.
    function executeIfAttested(
        bytes calldata rawQuote,
        bytes32 decisionHash,
        address enclave
    ) external {
        (bool ok, bytes memory output) = dcap.verifyAndAttestOnChain(rawQuote);
        if (!ok) revert QuoteVerificationFailed(output);

        bytes32 got = reportDataBinding(rawQuote);
        bytes32 want = expectedBinding(decisionHash, enclave);
        if (got != want) revert BindingMismatch(want, got);

        attestedCount += 1;
        emit ActionExecuted(decisionHash, enclave);
    }

    /// @dev address -> its 42-byte "0x…" lowercase-hex ASCII representation,
    ///      the exact bytes eth_account's address.lower().encode() yields.
    function _toLowerHexBytes(address a) internal pure returns (bytes memory) {
        bytes16 hexdigits = "0123456789abcdef";
        bytes memory s = new bytes(42);
        s[0] = "0";
        s[1] = "x";
        uint160 v = uint160(a);
        for (uint256 i = 0; i < 20; i++) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            s[2 + i * 2] = hexdigits[b >> 4];
            s[3 + i * 2] = hexdigits[b & 0x0f];
        }
        return s;
    }
}
