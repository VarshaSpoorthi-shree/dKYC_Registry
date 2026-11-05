// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FunctionsClient} from "@chainlink/contracts/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import {FunctionsRequest} from "@chainlink/contracts/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";
import {ConfirmedOwner} from "@chainlink/contracts/src/v0.8/shared/access/ConfirmedOwner.sol";

interface IKYCRegistry {
    function fulfillScreening(bytes32 requestId, bool hit, bytes32 evidenceHash, string calldata source) external;
    function screeningRequests(bytes32) external view returns (address subject, uint64 requestedAt, bool fulfilled, uint8 clearVotes, uint8 hitVotes);
}

/**
 * @title  KYCScreeningFunctions — Chainlink Functions adapter (testnet / production path)
 * @notice Decentralised alternative to the local oracle node in /server/oracle.js.
 *         Grant this contract ORACLE_ROLE on the KYCRegistry. When the registry emits
 *         ScreeningRequested, anyone (e.g. a Chainlink Automation log trigger) calls
 *         `screen(requestId)`. The DON runs /chainlink/screening-source.js, which:
 *           1. fetches the applicant's name from the consent-gated vault API using a
 *              DON-hosted secret (PII never touches the chain), and
 *           2. queries a sanctions / PEP API (OpenSanctions),
 *         then returns abi.encode(bool hit, bytes32 evidenceHash).
 */
contract KYCScreeningFunctions is FunctionsClient, ConfirmedOwner {
    using FunctionsRequest for FunctionsRequest.Request;

    IKYCRegistry public immutable registry;
    string public source; // JavaScript executed by the DON
    uint64 public subscriptionId;
    uint32 public gasLimit = 300_000;
    bytes32 public donId;
    uint8 public secretsSlotId;
    uint64 public secretsVersion;

    mapping(bytes32 => bytes32) public chainlinkToRegistryRequest;

    event ScreeningSent(bytes32 indexed chainlinkRequestId, bytes32 indexed registryRequestId);
    event ScreeningError(bytes32 indexed chainlinkRequestId, bytes err);

    error AlreadyFulfilled();
    error UnknownRequest();

    constructor(address router, address registry_, bytes32 donId_, uint64 subscriptionId_)
        FunctionsClient(router)
        ConfirmedOwner(msg.sender)
    {
        registry = IKYCRegistry(registry_);
        donId = donId_;
        subscriptionId = subscriptionId_;
    }

    function setSource(string calldata js) external onlyOwner { source = js; }

    function setSecrets(uint8 slotId, uint64 version) external onlyOwner {
        secretsSlotId = slotId;
        secretsVersion = version;
    }

    function setGasLimit(uint32 g) external onlyOwner { gasLimit = g; }

    /// @notice Forward a registry screening request to the Chainlink DON.
    function screen(bytes32 registryRequestId) external returns (bytes32 clRequestId) {
        (address subject,, bool fulfilled,,) = registry.screeningRequests(registryRequestId);
        if (subject == address(0)) revert UnknownRequest();
        if (fulfilled) revert AlreadyFulfilled();

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(source);
        if (secretsVersion > 0) req.addDONHostedSecrets(secretsSlotId, secretsVersion);
        string[] memory args = new string[](1);
        args[0] = _toHex(subject); // only the pseudonymous address goes on-chain
        req.setArgs(args);

        clRequestId = _sendRequest(req.encodeCBOR(), subscriptionId, gasLimit, donId);
        chainlinkToRegistryRequest[clRequestId] = registryRequestId;
        emit ScreeningSent(clRequestId, registryRequestId);
    }

    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal override {
        bytes32 registryRequestId = chainlinkToRegistryRequest[requestId];
        if (err.length > 0 || response.length == 0) {
            emit ScreeningError(requestId, err);
            return; // leave the registry request pending; it can be retried
        }
        (bool hit, bytes32 evidenceHash) = abi.decode(response, (bool, bytes32));
        registry.fulfillScreening(registryRequestId, hit, evidenceHash, "chainlink-functions:opensanctions");
    }

    function _toHex(address a) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes20 data = bytes20(a);
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(data[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
}
