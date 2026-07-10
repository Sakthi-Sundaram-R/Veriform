// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title VeriformRegistry
/// @notice On-chain anchor for Veriform's enclave-signed decisions.
///         Stores the address of the key that a genuine, attested enclave
///         derived, and lets any contract check that a decision was signed
///         by that key. This is the on-chain half of the off-chain verifier:
///         the same secp256k1 signature check, enforced by the EVM.
///
/// The agent signs the canonical decision payload with EIP-191 personal_sign
/// (the eth_account default). To verify on-chain, a caller passes:
///   - decisionDigest: the EIP-191 digest, i.e.
///       keccak256("\x19Ethereum Signed Message:\n32" || keccak256(canonical))
///     (Veriform uses SHA-256 for its off-chain binding; for the on-chain path
///      the payload is hashed with keccak256 so ecrecover can consume it.)
///   - signature: 65-byte {r,s,v} from the enclave key
contract VeriformRegistry {
    /// @notice The enclave-attested signer. Actions are trusted only from this key.
    address public attestedAgent;

    /// @notice Who may rotate the attested agent (e.g. after a re-attestation).
    address public owner;

    event AttestedAgentUpdated(address indexed previous, address indexed current);

    error NotOwner();
    error ZeroAddress();

    constructor(address _attestedAgent) {
        owner = msg.sender;
        attestedAgent = _attestedAgent;
        emit AttestedAgentUpdated(address(0), _attestedAgent);
    }

    /// @notice Rotate the attested key. In production this call would itself be
    ///         gated on a fresh remote-attestation proof; kept owner-gated here.
    function setAttestedAgent(address _agent) external {
        if (msg.sender != owner) revert NotOwner();
        if (_agent == address(0)) revert ZeroAddress();
        emit AttestedAgentUpdated(attestedAgent, _agent);
        attestedAgent = _agent;
    }

    /// @notice Recover the signer of an EIP-191 digest.
    function recover(bytes32 digest, bytes calldata signature)
        public
        pure
        returns (address)
    {
        require(signature.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        return ecrecover(digest, v, r, s);
    }

    /// @notice True iff `signature` over `decisionDigest` came from the
    ///         currently attested enclave key.
    function isVerifiedDecision(bytes32 decisionDigest, bytes calldata signature)
        public
        view
        returns (bool)
    {
        address signer = recover(decisionDigest, signature);
        return signer != address(0) && signer == attestedAgent;
    }
}
