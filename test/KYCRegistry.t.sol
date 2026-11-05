// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract KYCRegistryTest is Test {
    KYCRegistry reg;

    address admin = makeAddr("regulator");
    address provider = makeAddr("provider");
    address provider2 = makeAddr("provider2");
    address bankA = makeAddr("bankA");
    address bankB = makeAddr("bankB");
    address oracle = makeAddr("oracle");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address mallory = makeAddr("mallory");

    bytes32 constant AGE = keccak256("AGE_OVER_18");
    bytes32 constant NAT = keccak256("NATIONALITY");
    bytes32 constant SALT_AGE = keccak256("salt-age");
    bytes32 constant SALT_NAT = keccak256("salt-nat");
    bytes32 constant ID_SALT = keccak256("id-salt");

    bytes32 commitment;
    bytes32 constant DOC_HASH = keccak256("encrypted-bundle");

    function setUp() public {
        reg = new KYCRegistry(admin);
        vm.startPrank(admin);
        reg.registerOrganization(provider, reg.PROVIDER_ROLE(), "TrustVerify KYC");
        reg.registerOrganization(provider2, reg.PROVIDER_ROLE(), "Other KYC");
        reg.registerOrganization(bankA, reg.INSTITUTION_ROLE(), "Bank Alpha");
        reg.registerOrganization(bankB, reg.INSTITUTION_ROLE(), "Bank Beta");
        reg.registerOrganization(oracle, reg.ORACLE_ROLE(), "Screening Oracle");
        vm.stopPrank();
        commitment = keccak256(abi.encode(alice, "ALICE SHARMA", "1995-04-12", "ABCDE1234F", ID_SALT));
    }

    // ───────── helpers ─────────
    function _register(address user) internal {
        vm.prank(user);
        reg.registerIdentity(commitment, DOC_HASH, "vault://doc-1");
    }

    function _verify(address user) internal returns (bytes32 requestId) {
        bytes32[] memory keys = new bytes32[](2);
        bytes32[] memory comms = new bytes32[](2);
        keys[0] = AGE;
        keys[1] = NAT;
        comms[0] = reg.attributeCommitment(user, AGE, "true", SALT_AGE);
        comms[1] = reg.attributeCommitment(user, NAT, "IN", SALT_NAT);
        vm.recordLogs();
        vm.prank(provider);
        reg.decideVerification(user, true, 2, KYCRegistry.RiskLevel.Low, 365, keys, comms);
        // pull requestId from ScreeningRequested event
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("ScreeningRequested(bytes32,address,address)")) return logs[i].topics[1];
        }
        revert("no screening request");
    }

    function _fullOnboard(address user, bool sanctionsHit) internal {
        _register(user);
        bytes32 rid = _verify(user);
        vm.prank(oracle);
        reg.fulfillScreening(rid, sanctionsHit, keccak256("report"), "test");
    }

    // ───────── registration ─────────
    function test_RegisterStoresOnlyCommitments() public {
        _register(alice);
        vm.prank(alice);
        KYCRegistry.Identity memory id = reg.getIdentity(alice);
        assertEq(uint8(id.status), uint8(KYCRegistry.KYCStatus.Pending));
        assertEq(id.identityCommitment, commitment);
        assertEq(id.documentHash, DOC_HASH);
        assertEq(reg.subjectCount(), 1);
    }

    function test_RevertWhen_RegisteringTwiceWhilePending() public {
        _register(alice);
        vm.expectRevert(KYCRegistry.AlreadyRegistered.selector);
        _register(alice);
    }

    function test_RevertWhen_EmptyCommitment() public {
        vm.prank(alice);
        vm.expectRevert(KYCRegistry.InvalidInput.selector);
        reg.registerIdentity(bytes32(0), DOC_HASH, "vault://x");
    }

    function test_StrangerCannotReadIdentity() public {
        _register(alice);
        vm.prank(mallory);
        vm.expectRevert(KYCRegistry.NotAuthorized.selector);
        reg.getIdentity(alice);
    }

    // ───────── verification ─────────
    function test_OnlyProviderCanVerify() public {
        _register(alice);
        bytes32[] memory e = new bytes32[](0);
        bytes32 role = reg.PROVIDER_ROLE();
        vm.prank(bankA);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, bankA, role));
        reg.decideVerification(alice, true, 1, KYCRegistry.RiskLevel.Low, 30, e, e);
    }

    function test_VerifiedButNotValidUntilScreened() public {
        _register(alice);
        _verify(alice);
        assertFalse(reg.isKYCValid(alice), "must wait for sanctions screening");
        vm.prank(alice);
        assertEq(uint8(reg.getIdentity(alice).screening), uint8(KYCRegistry.ScreeningStatus.Pending));
    }

    function test_ValidAfterClearScreening() public {
        _fullOnboard(alice, false);
        assertTrue(reg.isKYCValid(alice));
    }

    function test_SanctionsHitInvalidatesKYC() public {
        _fullOnboard(alice, true);
        assertFalse(reg.isKYCValid(alice));
        vm.prank(alice);
        KYCRegistry.Identity memory id = reg.getIdentity(alice);
        assertEq(uint8(id.risk), uint8(KYCRegistry.RiskLevel.High));
        assertEq(uint8(id.screening), uint8(KYCRegistry.ScreeningStatus.Hit));
    }

    function test_RejectThenResubmit() public {
        _register(alice);
        bytes32[] memory e = new bytes32[](0);
        vm.prank(provider);
        reg.decideVerification(alice, false, 0, KYCRegistry.RiskLevel.Unassessed, 0, e, e);
        assertEq(uint8(reg.statusOf(alice)), uint8(KYCRegistry.KYCStatus.Rejected));
        _register(alice); // allowed again
        assertEq(uint8(reg.statusOf(alice)), uint8(KYCRegistry.KYCStatus.Pending));
    }

    function test_KYCExpires() public {
        _fullOnboard(alice, false);
        vm.warp(block.timestamp + 366 days);
        assertFalse(reg.isKYCValid(alice));
        _register(alice); // can renew after expiry
    }

    function test_OnlyVerifyingProviderOrAdminCanRevoke() public {
        _fullOnboard(alice, false);
        vm.prank(provider2);
        vm.expectRevert(KYCRegistry.NotAuthorized.selector);
        reg.revokeVerification(alice, "x");

        vm.prank(provider);
        reg.revokeVerification(alice, "document forgery");
        assertFalse(reg.isKYCValid(alice));
    }

    // ───────── oracle ─────────
    function test_OnlyOracleCanFulfill() public {
        _register(alice);
        bytes32 rid = _verify(alice);
        bytes32 role = reg.ORACLE_ROLE();
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, mallory, role));
        reg.fulfillScreening(rid, false, bytes32(0), "fake");
    }

    function test_RevertWhen_FulfillTwiceOrUnknown() public {
        _register(alice);
        bytes32 rid = _verify(alice);
        vm.startPrank(oracle);
        reg.fulfillScreening(rid, false, bytes32(0), "s");
        vm.expectRevert(KYCRegistry.AlreadyFulfilled.selector);
        reg.fulfillScreening(rid, false, bytes32(0), "s");
        vm.expectRevert(KYCRegistry.UnknownRequest.selector);
        reg.fulfillScreening(keccak256("nope"), false, bytes32(0), "s");
        vm.stopPrank();
    }

    function test_PerpetualRescreeningCanFlagLater() public {
        _fullOnboard(alice, false);
        assertTrue(reg.isKYCValid(alice));
        vm.prank(oracle);
        bytes32 rid = reg.requestScreening(alice);
        vm.prank(oracle);
        reg.fulfillScreening(rid, true, keccak256("new listing"), "ofac");
        assertFalse(reg.isKYCValid(alice));
    }

    function test_InstitutionWithoutRiskConsentCannotTriggerScreening() public {
        _fullOnboard(alice, false);
        vm.prank(bankA);
        vm.expectRevert(KYCRegistry.NotAuthorized.selector);
        reg.requestScreening(alice);
    }

    // ───────── consent & access ─────────
    function test_BankBlockedWithoutConsent() public {
        _fullOnboard(alice, false);
        vm.prank(bankA);
        vm.expectRevert(abi.encodeWithSelector(KYCRegistry.NoConsent.selector, uint8(1)));
        reg.accessKYC(alice);
    }

    function test_ConsentFlowEndToEnd() public {
        _fullOnboard(alice, false);

        vm.prank(bankA);
        reg.requestAccess(alice, 7, "Savings account opening");
        assertEq(reg.getAccessRequests(alice).length, 1);

        vm.prank(alice);
        reg.grantConsent(bankA, 1 | 2 | 4, 30);

        vm.prank(bankA);
        KYCRegistry.KYCView memory v = reg.accessKYC(alice);
        assertTrue(v.valid);
        assertEq(v.tier, 2);
        assertEq(v.verifiedBy, provider);
        assertEq(uint8(v.screening), uint8(KYCRegistry.ScreeningStatus.Clear));

        // other banks still blocked
        vm.prank(bankB);
        vm.expectRevert(abi.encodeWithSelector(KYCRegistry.NoConsent.selector, uint8(1)));
        reg.accessKYC(alice);
    }

    function test_StatusOnlyConsentHidesRisk() public {
        _fullOnboard(alice, false);
        vm.prank(alice);
        reg.grantConsent(bankA, 1, 30);
        vm.prank(bankA);
        KYCRegistry.KYCView memory v = reg.getKYCForInstitution(alice);
        assertTrue(v.valid);
        assertEq(uint8(v.risk), 0);
        assertEq(uint8(v.screening), 0);
    }

    function test_AccessIsAuditLogged() public {
        _fullOnboard(alice, false);
        vm.prank(alice);
        reg.grantConsent(bankA, 1, 30);
        vm.expectEmit(true, true, false, true);
        emit KYCRegistry.KYCAccessed(bankA, alice, 1, true, uint64(block.timestamp));
        vm.prank(bankA);
        reg.accessKYC(alice);
    }

    function test_ConsentExpires() public {
        _fullOnboard(alice, false);
        vm.prank(alice);
        reg.grantConsent(bankA, 1, 10);
        vm.warp(block.timestamp + 11 days);
        assertFalse(reg.hasConsent(alice, bankA, 1));
    }

    function test_RevokeConsent() public {
        _fullOnboard(alice, false);
        vm.startPrank(alice);
        reg.grantConsent(bankA, 15, 30);
        reg.revokeConsent(bankA);
        vm.stopPrank();
        vm.prank(bankA);
        vm.expectRevert(abi.encodeWithSelector(KYCRegistry.NoConsent.selector, uint8(1)));
        reg.accessKYC(alice);
    }

    function test_CannotConsentToNonInstitution() public {
        _register(alice);
        vm.prank(alice);
        vm.expectRevert(KYCRegistry.NotInstitution.selector);
        reg.grantConsent(mallory, 1, 30);
    }

    function test_DeregisteredInstitutionLosesAccess() public {
        _fullOnboard(alice, false);
        vm.prank(alice);
        reg.grantConsent(bankA, 1, 30);
        bytes32 role = reg.INSTITUTION_ROLE();
        vm.prank(admin);
        reg.revokeRole(role, bankA);
        assertFalse(reg.hasConsent(alice, bankA, 1));
    }

    // ───────── selective disclosure ─────────
    function test_SelectiveDisclosure() public {
        _fullOnboard(alice, false);
        vm.prank(alice);
        reg.grantConsent(bankA, 1 | 4, 30);

        vm.startPrank(bankA);
        assertTrue(reg.verifyAttribute(alice, AGE, "true", SALT_AGE));
        assertTrue(reg.verifyAttribute(alice, NAT, "IN", SALT_NAT));
        assertFalse(reg.verifyAttribute(alice, NAT, "US", SALT_NAT), "wrong value");
        assertFalse(reg.verifyAttribute(alice, NAT, "IN", SALT_AGE), "wrong salt");
        assertTrue(reg.matchesIdentityCommitment(alice, commitment));
        vm.stopPrank();
    }

    function test_AttributeCheckNeedsAttributeScope() public {
        _fullOnboard(alice, false);
        vm.prank(alice);
        reg.grantConsent(bankA, 1, 30);
        vm.prank(bankA);
        vm.expectRevert(abi.encodeWithSelector(KYCRegistry.NoConsent.selector, uint8(4)));
        reg.verifyAttribute(alice, AGE, "true", SALT_AGE);
    }

    function test_AttributeCommitmentBoundToUser() public {
        _fullOnboard(alice, false);
        // Bob cannot reuse Alice's commitment: commitments include the owner address
        assertTrue(reg.attributeCommitment(alice, AGE, "true", SALT_AGE) != reg.attributeCommitment(bob, AGE, "true", SALT_AGE));
    }

    // ───────── admin ─────────
    function test_PauseBlocksWrites() public {
        vm.prank(admin);
        reg.pause();
        vm.prank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        reg.registerIdentity(commitment, DOC_HASH, "vault://x");
    }

    function test_OnlyAdminRegistersOrgs() public {
        bytes32 role = reg.INSTITUTION_ROLE();
        vm.prank(mallory);
        vm.expectRevert();
        reg.registerOrganization(mallory, role, "Fake Bank");
    }

    // ───────── fuzz ─────────
    function testFuzz_ConsentScopesAreEnforced(uint8 scopes) public {
        scopes = uint8(bound(scopes, 1, 15));
        _fullOnboard(alice, false);
        vm.prank(alice);
        reg.grantConsent(bankA, scopes, 30);
        for (uint8 s = 1; s <= 8; s <<= 1) {
            assertEq(reg.hasConsent(alice, bankA, s), scopes & s == s);
        }
    }
}
