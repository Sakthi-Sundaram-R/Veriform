// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VeriformRegistry} from "./VeriformRegistry.sol";

/// @title DemoConsumer
/// @notice Example of a contract that acts ONLY on decisions a verified
///         Veriform enclave approved. The evil agent's signature — produced
///         outside any enclave — recovers to a different address and is
///         rejected here exactly as it is in the off-chain verifier UI.
contract DemoConsumer {
    VeriformRegistry public immutable registry;

    uint256 public approvedCount;
    event ActionExecuted(bytes32 indexed decisionDigest);

    error UnverifiedDecision();

    constructor(VeriformRegistry _registry) {
        registry = _registry;
    }

    /// @notice Execute a guarded action. Reverts unless the decision was
    ///         signed by the attested enclave key.
    function executeIfApproved(bytes32 decisionDigest, bytes calldata signature)
        external
    {
        if (!registry.isVerifiedDecision(decisionDigest, signature)) {
            revert UnverifiedDecision();
        }
        approvedCount += 1;
        emit ActionExecuted(decisionDigest);
    }
}
