// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";

/// Tests for the two research extensions:
///  (1) k-of-n oracle quorum with escalation to regulator review
///  (2) per-institution freshness policy enforced at read time
contract QuorumFreshnessTest is Test {
    KYCRegistry reg;

    address admin = makeAddr("regulator");
    address provider = makeAddr("provider");
    address bankA = makeAddr("bankA");
    address bankB = makeAddr("bankB");
    address o1 = makeAddr("oracle1");
    address o2 = makeAddr("oracle2");
    address o3 = makeAddr("oracle3");
    address alice = makeAddr("alice");

    bytes32 constant DOC = keccak256("doc");

    function setUp() public {
        reg = new KYCRegistry(admin);
        vm.startPrank(admin);
        reg.registerOrganization(provider, reg.PROVIDER_ROLE(), "Provider");
        reg.registerOrganization(bankA, reg.INSTITUTION_ROLE(), "Bank A");
        reg.registerOrganization(bankB, reg.INSTITUTION_ROLE(), "Bank B");
        reg.registerOrganization(o1, reg.ORACLE_ROLE(), "Oracle 1");
        reg.registerOrganization(o2, reg.ORACLE_ROLE(), "Oracle 2");
        reg.registerOrganization(o3, reg.ORACLE_ROLE(), "Oracle 3");
        vm.stopPrank();
    }

    // ───────── helpers ─────────
    function _verify() internal returns (bytes32 rid) {
        vm.prank(alice);
        reg.registerIdentity(keccak256("commitment"), DOC, "vault://x");
        bytes32[] memory e = new bytes32[](0);
        vm.recordLogs();
        vm.prank(provider);
        reg.decideVerification(alice, true, 2, KYCRegistry.RiskLevel.Low, 365, e, e);
        rid = _lastRequestId();
    }

    function _lastRequestId() internal returns (bytes32) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sig = keccak256("ScreeningRequested(bytes32,address,address)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] == sig) return logs[i - 1].topics[1];
        }
        revert("no request");
    }

    function _vote(address oracle, bytes32 rid, bool hit) internal {
        vm.prank(oracle);
        reg.fulfillScreening(rid, hit, keccak256(abi.encode(oracle, hit)), "test");
    }

    function _screening() internal returns (KYCRegistry.ScreeningStatus) {
        vm.prank(alice);
        return reg.getIdentity(alice).screening;
    }

    function _setQuorum(uint8 k) internal {
        vm.prank(admin);
        reg.setScreeningQuorum(k);
    }

    // ═════════════════════ (1) oracle quorum ═════════════════════
    function test_OracleCountTracksRoles() public {
        assertEq(reg.oracleCount(), 3);
        bytes32 role = reg.ORACLE_ROLE();
        vm.prank(admin);
        reg.revokeRole(role, o3);
        assertEq(reg.oracleCount(), 2);
    }

    function test_QuorumCannotExceedOracleCount() public {
        vm.prank(admin);
        vm.expectRevert(KYCRegistry.InvalidInput.selector);
        reg.setScreeningQuorum(4);
        vm.prank(admin);
        vm.expectRevert(KYCRegistry.InvalidInput.selector);
        reg.setScreeningQuorum(0);
    }

    function test_OnlyAdminSetsQuorum() public {
        vm.prank(bankA);
        vm.expectRevert();
        reg.setScreeningQuorum(2);
    }

    function test_QuorumShrinksWhenOracleRemoved() public {
        _setQuorum(3);
        bytes32 role = reg.ORACLE_ROLE();
        vm.prank(admin);
        reg.revokeRole(role, o3);
        assertEq(reg.screeningQuorum(), 2, "quorum must stay reachable");
    }

    function test_SingleVoteNotFinalWithQuorumTwo() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        assertEq(uint8(_screening()), uint8(KYCRegistry.ScreeningStatus.Pending));
        assertFalse(reg.isKYCValid(alice));
        (,, bool fulfilled, uint8 c, uint8 h) = reg.screeningRequests(rid);
        assertFalse(fulfilled);
        assertEq(c, 1);
        assertEq(h, 0);
    }

    function test_UnanimousClearFinalises() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        _vote(o2, rid, false);
        assertEq(uint8(_screening()), uint8(KYCRegistry.ScreeningStatus.Clear));
        assertTrue(reg.isKYCValid(alice));
    }

    function test_UnanimousHitFinalises() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, true);
        _vote(o2, rid, true);
        assertEq(uint8(_screening()), uint8(KYCRegistry.ScreeningStatus.Hit));
        vm.prank(alice);
        assertEq(uint8(reg.getIdentity(alice).risk), uint8(KYCRegistry.RiskLevel.High));
    }

    function test_DisagreementEscalatesToReview() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        vm.expectEmit(true, true, false, true);
        emit KYCRegistry.ScreeningEscalated(rid, alice, 1, 1);
        _vote(o2, rid, true);
        assertEq(uint8(_screening()), uint8(KYCRegistry.ScreeningStatus.Review));
        assertFalse(reg.isKYCValid(alice), "a disputed record must not be usable");
    }

    function test_RegulatorResolvesReview() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        _vote(o2, rid, true);
        vm.prank(admin);
        reg.resolveReview(alice, false, "false positive: different date of birth");
        assertTrue(reg.isKYCValid(alice));
    }

    function test_OnlyAdminResolvesReview() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        _vote(o2, rid, true);
        vm.prank(bankA);
        vm.expectRevert();
        reg.resolveReview(alice, false, "x");
    }

    function test_ResolveRequiresReviewState() public {
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        vm.prank(admin);
        vm.expectRevert(KYCRegistry.NotInReview.selector);
        reg.resolveReview(alice, true, "x");
    }

    function test_OracleCannotVoteTwice() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        vm.prank(o1);
        vm.expectRevert(KYCRegistry.AlreadyVoted.selector);
        reg.fulfillScreening(rid, false, bytes32(0), "again");
    }

    function test_LateVoteAfterFinalisationRejected() public {
        _setQuorum(2);
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        _vote(o2, rid, false);
        vm.prank(o3);
        vm.expectRevert(KYCRegistry.AlreadyFulfilled.selector);
        reg.fulfillScreening(rid, true, bytes32(0), "late");
    }

    function test_SingleCompromisedOracleCannotClearAlone() public {
        _setQuorum(3);
        bytes32 rid = _verify();
        _vote(o1, rid, false); // compromised oracle says clear
        assertFalse(reg.isKYCValid(alice));
        _vote(o2, rid, true); // honest oracles report the hit
        _vote(o3, rid, true);
        assertEq(uint8(_screening()), uint8(KYCRegistry.ScreeningStatus.Review));
        assertFalse(reg.isKYCValid(alice));
    }

    function test_RescreenKeepsServiceUntilResult() public {
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        assertTrue(reg.isKYCValid(alice));
        vm.prank(o1);
        reg.requestScreening(alice); // periodic re-screen
        assertTrue(reg.isKYCValid(alice), "re-screen must not interrupt a clear record");
    }

    /// Fuzz: for any vote pattern of 3 oracles with quorum 3, the outcome is
    /// Clear iff all clear, Hit iff all hit, otherwise Review.
    function testFuzz_QuorumOutcome(bool v1, bool v2, bool v3) public {
        _setQuorum(3);
        bytes32 rid = _verify();
        _vote(o1, rid, v1);
        _vote(o2, rid, v2);
        _vote(o3, rid, v3);
        KYCRegistry.ScreeningStatus s = _screening();
        if (!v1 && !v2 && !v3) assertEq(uint8(s), uint8(KYCRegistry.ScreeningStatus.Clear));
        else if (v1 && v2 && v3) assertEq(uint8(s), uint8(KYCRegistry.ScreeningStatus.Hit));
        else assertEq(uint8(s), uint8(KYCRegistry.ScreeningStatus.Review));
    }

    // ═════════════════════ (2) freshness policy ═════════════════════
    function _verifiedAndClear() internal {
        bytes32 rid = _verify();
        _vote(o1, rid, false);
        vm.startPrank(alice);
        reg.grantConsent(bankA, 1 | 2, 365);
        reg.grantConsent(bankB, 1 | 2, 365);
        vm.stopPrank();
    }

    function test_OnlyInstitutionSetsPolicy() public {
        vm.prank(alice);
        vm.expectRevert();
        reg.setFreshnessPolicy(1 days);
    }

    function test_PolicyBounds() public {
        vm.startPrank(bankA);
        vm.expectRevert(KYCRegistry.InvalidInput.selector);
        reg.setFreshnessPolicy(30 minutes);
        vm.expectRevert(KYCRegistry.InvalidInput.selector);
        reg.setFreshnessPolicy(400 days);
        reg.setFreshnessPolicy(0); // disabling is allowed
        reg.setFreshnessPolicy(1 days);
        vm.stopPrank();
        assertEq(reg.freshnessPolicy(bankA), 1 days);
    }

    function test_StaleScreeningInvalidForStrictBankOnly() public {
        _verifiedAndClear();
        vm.prank(bankA);
        reg.setFreshnessPolicy(1 days); // strict bank
        vm.prank(bankB);
        reg.setFreshnessPolicy(30 days); // lenient bank

        vm.warp(block.timestamp + 2 days);
        assertTrue(reg.isKYCValid(alice), "globally still valid");
        assertFalse(reg.isKYCValidFor(alice, bankA), "too stale for Bank A");
        assertTrue(reg.isKYCValidFor(alice, bankB), "fresh enough for Bank B");

        vm.prank(bankA);
        KYCRegistry.KYCView memory va = reg.accessKYC(alice);
        assertFalse(va.valid);
        assertFalse(va.fresh);
        vm.prank(bankB);
        KYCRegistry.KYCView memory vb = reg.accessKYC(alice);
        assertTrue(vb.valid);
    }

    function test_BankRestoresFreshnessByRescreening() public {
        _verifiedAndClear();
        vm.prank(bankA);
        reg.setFreshnessPolicy(1 days);
        vm.warp(block.timestamp + 2 days);
        assertFalse(reg.isKYCValidFor(alice, bankA));

        vm.recordLogs();
        vm.prank(bankA); // allowed because it holds RISK consent
        reg.requestScreening(alice);
        bytes32 rid = _lastRequestId();
        _vote(o1, rid, false);
        assertTrue(reg.isKYCValidFor(alice, bankA));
    }

    function test_NoPolicyMeansNoFreshnessCheck() public {
        _verifiedAndClear();
        vm.warp(block.timestamp + 300 days);
        assertTrue(reg.isKYCValidFor(alice, bankA));
    }

    function testFuzz_FreshnessBoundary(uint64 policy, uint64 elapsed) public {
        policy = uint64(bound(policy, 1 hours, 365 days));
        elapsed = uint64(bound(elapsed, 0, 365 days));
        _verifiedAndClear();
        vm.prank(bankA);
        reg.setFreshnessPolicy(policy);
        vm.warp(block.timestamp + elapsed);
        assertEq(reg.isScreeningFresh(alice, bankA), elapsed <= policy);
    }
}
