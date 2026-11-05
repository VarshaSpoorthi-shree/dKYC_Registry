// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title  KYCRegistry — Decentralized KYC / Digital Identity Sharing Registry
 * @notice "KYC once, reuse everywhere". A customer completes KYC with one accredited
 *         provider; any other regulated institution can rely on that verification
 *         ONLY with the customer's explicit, scoped, time-bound, revocable consent.
 *
 * Privacy model
 *  - No PII is ever written on-chain. The chain stores:
 *      * identityCommitment = keccak256(abi.encode(owner, fullName, dob, idNumber, salt))
 *      * documentHash       = sha256 of the encrypted document bundle held off-chain
 *      * attribute commitments (selective disclosure), e.g. AGE_OVER_18 = true
 *  - The off-chain vault releases documents only after checking on-chain consent,
 *    and institutions verify disclosed values against on-chain commitments.
 *
 * Compliance model
 *  - A KYC record is only "valid" when: Verified, not expired, and the latest
 *    sanctions / PEP screening is Clear.
 *  - k-of-n oracle quorum: a screening is final only when `screeningQuorum` independent
 *    oracles agree. Unanimous clear => Clear, unanimous hit => Hit, any disagreement
 *    => Review (record unusable until the regulator resolves it).
 *  - Freshness-bound reuse: each institution may set a maximum screening age; the record
 *    is valid *for that institution* only if the last screening is recent enough.
 *  - Every institutional access is logged as an event => immutable audit trail.
 */
contract KYCRegistry is AccessControl, Pausable {
    // ───────────────────────────── Roles ─────────────────────────────
    bytes32 public constant PROVIDER_ROLE = keccak256("PROVIDER_ROLE"); // accredited KYC verifiers
    bytes32 public constant INSTITUTION_ROLE = keccak256("INSTITUTION_ROLE"); // banks / FinTechs (consumers)
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE"); // sanctions / PEP screening oracle

    // ───────────────────────── Consent scopes (bitmask) ─────────────────────────
    uint8 public constant SCOPE_STATUS = 1; // status, tier, expiry, identity-commitment match
    uint8 public constant SCOPE_RISK = 2; // risk level + screening result
    uint8 public constant SCOPE_ATTRIBUTES = 4; // verify selectively-disclosed attributes
    uint8 public constant SCOPE_DOCUMENTS = 8; // download encrypted documents from vault
    uint8 public constant ALL_SCOPES = 15;

    uint64 public constant MAX_CONSENT_DAYS = 365;
    uint64 public constant MAX_VALIDITY_DAYS = 730;
    uint256 public constant MAX_ATTRIBUTES = 16;
    uint8 public constant MAX_QUORUM = 7;
    uint64 public constant MIN_FRESHNESS = 1 hours;
    uint64 public constant MAX_FRESHNESS = 365 days;

    // ───────────────────────────── Types ─────────────────────────────
    enum KYCStatus { None, Pending, Verified, Rejected, Revoked }
    enum RiskLevel { Unassessed, Low, Medium, High }
    enum ScreeningStatus { NotScreened, Pending, Clear, Hit, Review }

    struct Identity {
        bytes32 identityCommitment;
        bytes32 documentHash;
        string vaultURI;
        address verifiedBy;
        uint64 registeredAt;
        uint64 verifiedAt;
        uint64 expiresAt;
        uint64 lastScreenedAt;
        KYCStatus status;
        RiskLevel risk;
        ScreeningStatus screening;
        uint8 tier; // 1 = basic, 2 = standard, 3 = enhanced due diligence
    }

    struct Consent {
        uint64 grantedAt;
        uint64 expiresAt;
        uint8 scopes;
        bool active;
    }

    struct AccessRequest {
        address institution;
        uint8 scopes;
        uint64 requestedAt;
        string purpose;
    }

    struct ScreeningRequest {
        address subject;
        uint64 requestedAt;
        bool fulfilled;
        uint8 clearVotes;
        uint8 hitVotes;
    }

    /// Read model returned to institutions (no PII)
    struct KYCView {
        KYCStatus status;
        uint8 tier;
        uint64 verifiedAt;
        uint64 expiresAt;
        address verifiedBy;
        bool valid; // valid for the calling institution (includes its freshness policy)
        bool fresh; // last screening satisfies the caller's freshness policy
        RiskLevel risk; // only populated with SCOPE_RISK
        ScreeningStatus screening; // only populated with SCOPE_RISK
        uint64 lastScreenedAt; // only populated with SCOPE_RISK
    }

    // ──────────────────────────── Storage ────────────────────────────
    mapping(address => Identity) private _identities;
    mapping(address => mapping(bytes32 => bytes32)) private _attributes; // user => attrKey => commitment
    mapping(address => bytes32[]) private _attributeKeys;
    mapping(address => mapping(address => Consent)) private _consents; // user => institution => consent
    mapping(address => address[]) private _consentedInstitutions;
    mapping(address => mapping(address => bool)) private _everConsented;
    mapping(address => AccessRequest[]) private _accessRequests;
    mapping(address => string) public orgName; // display name for providers / institutions
    mapping(bytes32 => ScreeningRequest) public screeningRequests;
    mapping(bytes32 => mapping(address => bool)) public hasVoted; // requestId => oracle => voted
    mapping(address => uint64) public freshnessPolicy; // institution => max screening age (0 = none)
    uint8 public screeningQuorum = 1;
    uint8 public oracleCount;
    address[] private _subjects;
    uint256 private _screeningNonce;

    // ──────────────────────────── Events ─────────────────────────────
    event OrganizationRegistered(address indexed org, bytes32 indexed role, string name);
    event IdentityRegistered(address indexed user, bytes32 identityCommitment, bytes32 documentHash, string vaultURI);
    event VerificationDecided(address indexed user, address indexed provider, KYCStatus status, uint8 tier, RiskLevel risk, uint64 expiresAt);
    event VerificationRevoked(address indexed user, address indexed by, string reason);
    event AttributeAnchored(address indexed user, bytes32 indexed attrKey, bytes32 commitment);
    event AccessRequested(address indexed user, address indexed institution, uint8 scopes, string purpose);
    event ConsentGranted(address indexed user, address indexed institution, uint8 scopes, uint64 expiresAt);
    event ConsentRevoked(address indexed user, address indexed institution);
    event KYCAccessed(address indexed institution, address indexed user, uint8 scopes, bool valid, uint64 at);
    event ScreeningRequested(bytes32 indexed requestId, address indexed subject, address indexed requester);
    event ScreeningFulfilled(bytes32 indexed requestId, address indexed subject, bool hit, bytes32 evidenceHash, string source);
    event ScreeningVote(bytes32 indexed requestId, address indexed subject, address indexed oracle, bool hit, bytes32 evidenceHash, string source);
    event ScreeningEscalated(bytes32 indexed requestId, address indexed subject, uint8 clearVotes, uint8 hitVotes);
    event ReviewResolved(address indexed user, address indexed by, bool hit, string reason);
    event ScreeningQuorumSet(uint8 quorum);
    event FreshnessPolicySet(address indexed institution, uint64 maxAge);

    // ──────────────────────────── Errors ─────────────────────────────
    error InvalidAddress();
    error InvalidInput();
    error AlreadyRegistered();
    error NotRegistered();
    error NotPending();
    error NotVerified();
    error NotInstitution();
    error NoConsent(uint8 requiredScope);
    error UnknownRequest();
    error AlreadyFulfilled();
    error NotAuthorized();
    error AlreadyVoted();
    error NotInReview();

    constructor(address admin) {
        if (admin == address(0)) revert InvalidAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // ═════════════════════ Admin / Regulator functions ═════════════════════

    /// @notice Onboard an organisation with a role and a display name.
    function registerOrganization(address org, bytes32 role, string calldata name) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (org == address(0)) revert InvalidAddress();
        if (role != PROVIDER_ROLE && role != INSTITUTION_ROLE && role != ORACLE_ROLE) revert InvalidInput();
        if (bytes(name).length == 0 || bytes(name).length > 64) revert InvalidInput();
        _grantRole(role, org);
        orgName[org] = name;
        emit OrganizationRegistered(org, role, name);
    }

    /// @notice Number of independent oracles that must agree before a screening is final.
    function setScreeningQuorum(uint8 k) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (k == 0 || k > MAX_QUORUM || k > oracleCount) revert InvalidInput();
        screeningQuorum = k;
        emit ScreeningQuorumSet(k);
    }

    /// @notice Resolve a screening on which the oracles disagreed.
    function resolveReview(address user, bool hit, string calldata reason) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Identity storage id = _identities[user];
        if (id.screening != ScreeningStatus.Review) revert NotInReview();
        id.lastScreenedAt = uint64(block.timestamp);
        if (hit) {
            id.screening = ScreeningStatus.Hit;
            id.risk = RiskLevel.High;
        } else {
            id.screening = ScreeningStatus.Clear;
        }
        emit ReviewResolved(user, msg.sender, hit, reason);
    }

    // keep an exact count of oracles so the quorum can never exceed it
    function _grantRole(bytes32 role, address account) internal override returns (bool granted) {
        granted = super._grantRole(role, account);
        if (granted && role == ORACLE_ROLE) oracleCount++;
    }

    function _revokeRole(bytes32 role, address account) internal override returns (bool revoked) {
        revoked = super._revokeRole(role, account);
        if (revoked && role == ORACLE_ROLE) {
            oracleCount--;
            if (screeningQuorum > oracleCount && oracleCount > 0) {
                screeningQuorum = oracleCount;
                emit ScreeningQuorumSet(oracleCount);
            }
        }
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    // ═════════════════════════ Customer functions ═════════════════════════

    /// @notice Submit (or re-submit) identity commitments for verification.
    /// @dev Re-submission is allowed only if the record is Rejected, Revoked or expired.
    function registerIdentity(bytes32 identityCommitment, bytes32 documentHash, string calldata vaultURI) external whenNotPaused {
        if (identityCommitment == bytes32(0) || documentHash == bytes32(0)) revert InvalidInput();
        if (bytes(vaultURI).length == 0 || bytes(vaultURI).length > 200) revert InvalidInput();

        Identity storage id = _identities[msg.sender];
        if (id.status == KYCStatus.None) {
            _subjects.push(msg.sender);
        } else if (
            id.status == KYCStatus.Pending ||
            (id.status == KYCStatus.Verified && block.timestamp < id.expiresAt)
        ) {
            revert AlreadyRegistered();
        }

        // wipe old attribute commitments on re-submission
        bytes32[] storage keys = _attributeKeys[msg.sender];
        for (uint256 i = 0; i < keys.length; i++) delete _attributes[msg.sender][keys[i]];
        delete _attributeKeys[msg.sender];

        _identities[msg.sender] = Identity({
            identityCommitment: identityCommitment,
            documentHash: documentHash,
            vaultURI: vaultURI,
            verifiedBy: address(0),
            registeredAt: uint64(block.timestamp),
            verifiedAt: 0,
            expiresAt: 0,
            lastScreenedAt: 0,
            status: KYCStatus.Pending,
            risk: RiskLevel.Unassessed,
            screening: ScreeningStatus.NotScreened,
            tier: 0
        });
        emit IdentityRegistered(msg.sender, identityCommitment, documentHash, vaultURI);
    }

    /// @notice Grant an institution scoped, time-bound access to your KYC.
    function grantConsent(address institution, uint8 scopes, uint64 durationDays) external whenNotPaused {
        if (!hasRole(INSTITUTION_ROLE, institution)) revert NotInstitution();
        if (scopes == 0 || scopes > ALL_SCOPES) revert InvalidInput();
        if (durationDays == 0 || durationDays > MAX_CONSENT_DAYS) revert InvalidInput();
        if (_identities[msg.sender].status == KYCStatus.None) revert NotRegistered();

        uint64 exp = uint64(block.timestamp) + durationDays * 1 days;
        _consents[msg.sender][institution] = Consent(uint64(block.timestamp), exp, scopes, true);
        if (!_everConsented[msg.sender][institution]) {
            _everConsented[msg.sender][institution] = true;
            _consentedInstitutions[msg.sender].push(institution);
        }
        emit ConsentGranted(msg.sender, institution, scopes, exp);
    }

    /// @notice Revoke an institution's access immediately.
    function revokeConsent(address institution) external {
        Consent storage c = _consents[msg.sender][institution];
        if (!c.active) revert NoConsent(0);
        c.active = false;
        emit ConsentRevoked(msg.sender, institution);
    }

    // ═════════════════════════ Provider functions ═════════════════════════

    /**
     * @notice Record the verification decision after reviewing the off-chain documents.
     * @param attrKeys        e.g. keccak256("AGE_OVER_18")
     * @param attrCommitments keccak256(abi.encode(user, attrKey, value, salt)) supplied by the user and
     *                        checked by the provider against the documents before anchoring.
     */
    function decideVerification(
        address user,
        bool approve,
        uint8 tier,
        RiskLevel risk,
        uint64 validityDays,
        bytes32[] calldata attrKeys,
        bytes32[] calldata attrCommitments
    ) external onlyRole(PROVIDER_ROLE) whenNotPaused {
        Identity storage id = _identities[user];
        if (id.status != KYCStatus.Pending) revert NotPending();

        if (!approve) {
            id.status = KYCStatus.Rejected;
            id.verifiedBy = msg.sender;
            emit VerificationDecided(user, msg.sender, KYCStatus.Rejected, 0, RiskLevel.Unassessed, 0);
            return;
        }

        if (tier == 0 || tier > 3 || risk == RiskLevel.Unassessed) revert InvalidInput();
        if (validityDays == 0 || validityDays > MAX_VALIDITY_DAYS) revert InvalidInput();
        if (attrKeys.length != attrCommitments.length || attrKeys.length > MAX_ATTRIBUTES) revert InvalidInput();

        id.status = KYCStatus.Verified;
        id.tier = tier;
        id.risk = risk;
        id.verifiedBy = msg.sender;
        id.verifiedAt = uint64(block.timestamp);
        id.expiresAt = uint64(block.timestamp) + validityDays * 1 days;

        for (uint256 i = 0; i < attrKeys.length; i++) {
            if (attrCommitments[i] == bytes32(0)) revert InvalidInput();
            if (_attributes[user][attrKeys[i]] == bytes32(0)) _attributeKeys[user].push(attrKeys[i]);
            _attributes[user][attrKeys[i]] = attrCommitments[i];
            emit AttributeAnchored(user, attrKeys[i], attrCommitments[i]);
        }
        emit VerificationDecided(user, msg.sender, KYCStatus.Verified, tier, risk, id.expiresAt);

        // Every new verification is immediately screened against sanctions / PEP lists.
        _requestScreening(user);
    }

    /// @notice Revoke a verification (e.g. fraud detected). Only the verifying provider or the admin.
    function revokeVerification(address user, string calldata reason) external whenNotPaused {
        Identity storage id = _identities[user];
        if (id.status != KYCStatus.Verified) revert NotVerified();
        if (!(id.verifiedBy == msg.sender && hasRole(PROVIDER_ROLE, msg.sender)) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAuthorized();
        }
        id.status = KYCStatus.Revoked;
        emit VerificationRevoked(user, msg.sender, reason);
    }

    // ═══════════════════ Sanctions / PEP screening (oracle) ═══════════════════

    /// @notice Ask the oracle to (re-)screen a verified customer. Providers, the oracle itself
    ///         (perpetual KYC) and institutions holding SCOPE_RISK consent may call it.
    function requestScreening(address user) external whenNotPaused returns (bytes32) {
        if (_identities[user].status != KYCStatus.Verified) revert NotVerified();
        if (
            !hasRole(PROVIDER_ROLE, msg.sender) &&
            !hasRole(ORACLE_ROLE, msg.sender) &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender) &&
            !hasConsent(user, msg.sender, SCOPE_RISK)
        ) revert NotAuthorized();
        return _requestScreening(user);
    }

    function _requestScreening(address user) internal returns (bytes32 requestId) {
        requestId = keccak256(abi.encode(user, block.chainid, ++_screeningNonce));
        screeningRequests[requestId] = ScreeningRequest(user, uint64(block.timestamp), false, 0, 0);
        // A first screening blocks use; a re-screen keeps the last final result until the new one
        // arrives, so service is not interrupted (freshness policies bound how stale it may be).
        if (_identities[user].screening == ScreeningStatus.NotScreened) {
            _identities[user].screening = ScreeningStatus.Pending;
        }
        emit ScreeningRequested(requestId, user, msg.sender);
    }

    /// @notice One oracle's vote on a screening request. The request is finalised once
    ///         `screeningQuorum` distinct oracles have voted: unanimous clear => Clear,
    ///         unanimous hit => Hit, otherwise => Review (escalated to the regulator).
    /// @param evidenceHash hash of this oracle's off-chain screening report
    function fulfillScreening(bytes32 requestId, bool hit, bytes32 evidenceHash, string calldata source)
        external
        onlyRole(ORACLE_ROLE)
    {
        ScreeningRequest storage r = screeningRequests[requestId];
        if (r.subject == address(0)) revert UnknownRequest();
        if (r.fulfilled) revert AlreadyFulfilled();
        if (hasVoted[requestId][msg.sender]) revert AlreadyVoted();
        hasVoted[requestId][msg.sender] = true;
        if (hit) r.hitVotes++;
        else r.clearVotes++;
        emit ScreeningVote(requestId, r.subject, msg.sender, hit, evidenceHash, source);

        uint8 k = screeningQuorum;
        if (r.clearVotes + r.hitVotes < k) return; // wait for more oracles
        r.fulfilled = true;

        Identity storage id = _identities[r.subject];
        id.lastScreenedAt = uint64(block.timestamp);
        if (r.hitVotes == 0) {
            id.screening = ScreeningStatus.Clear;
            emit ScreeningFulfilled(requestId, r.subject, false, evidenceHash, source);
        } else if (r.clearVotes == 0) {
            id.screening = ScreeningStatus.Hit;
            id.risk = RiskLevel.High;
            emit ScreeningFulfilled(requestId, r.subject, true, evidenceHash, source);
        } else {
            id.screening = ScreeningStatus.Review;
            emit ScreeningEscalated(requestId, r.subject, r.clearVotes, r.hitVotes);
        }
    }

    // ═════════════════════════ Institution functions ═════════════════════════

    /// @notice An institution's compliance policy: the maximum age of the last sanctions screening
    ///         it accepts (0 disables the check). Enforced on every read by that institution.
    function setFreshnessPolicy(uint64 maxAge) external onlyRole(INSTITUTION_ROLE) {
        if (maxAge != 0 && (maxAge < MIN_FRESHNESS || maxAge > MAX_FRESHNESS)) revert InvalidInput();
        freshnessPolicy[msg.sender] = maxAge;
        emit FreshnessPolicySet(msg.sender, maxAge);
    }

    /// @notice Ask a customer for access. The customer approves with grantConsent().
    function requestAccess(address user, uint8 scopes, string calldata purpose) external onlyRole(INSTITUTION_ROLE) whenNotPaused {
        if (_identities[user].status == KYCStatus.None) revert NotRegistered();
        if (scopes == 0 || scopes > ALL_SCOPES || bytes(purpose).length > 140) revert InvalidInput();
        _accessRequests[user].push(AccessRequest(msg.sender, scopes, uint64(block.timestamp), purpose));
        emit AccessRequested(user, msg.sender, scopes, purpose);
    }

    /// @notice Audited KYC lookup: returns the record AND writes an access log event.
    function accessKYC(address user) external whenNotPaused returns (KYCView memory v) {
        v = getKYCForInstitution(user);
        Consent memory c = _consents[user][msg.sender];
        emit KYCAccessed(msg.sender, user, c.scopes, v.valid, uint64(block.timestamp));
    }

    /// @notice Consent-gated read (msg.sender must be the institution).
    function getKYCForInstitution(address user) public view returns (KYCView memory v) {
        if (!hasConsent(user, msg.sender, SCOPE_STATUS)) revert NoConsent(SCOPE_STATUS);
        Identity storage id = _identities[user];
        v.status = id.status;
        v.tier = id.tier;
        v.verifiedAt = id.verifiedAt;
        v.expiresAt = id.expiresAt;
        v.verifiedBy = id.verifiedBy;
        v.fresh = isScreeningFresh(user, msg.sender);
        v.valid = isKYCValid(user) && v.fresh;
        if (hasConsent(user, msg.sender, SCOPE_RISK)) {
            v.risk = id.risk;
            v.screening = id.screening;
            v.lastScreenedAt = id.lastScreenedAt;
        }
    }

    /// @notice Check PII handed over off-chain by the customer against the on-chain commitment.
    function matchesIdentityCommitment(address user, bytes32 commitment) external view returns (bool) {
        if (!hasConsent(user, msg.sender, SCOPE_STATUS)) revert NoConsent(SCOPE_STATUS);
        return _identities[user].identityCommitment == commitment;
    }

    /// @notice Selective disclosure: verify one attribute value without seeing any other data.
    function verifyAttribute(address user, bytes32 attrKey, string calldata value, bytes32 salt) external view returns (bool) {
        if (!hasConsent(user, msg.sender, SCOPE_ATTRIBUTES)) revert NoConsent(SCOPE_ATTRIBUTES);
        bytes32 stored = _attributes[user][attrKey];
        return stored != bytes32(0) && stored == attributeCommitment(user, attrKey, value, salt);
    }

    // ═════════════════════════════ Views ═════════════════════════════

    function attributeCommitment(address user, bytes32 attrKey, string calldata value, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(user, attrKey, value, salt));
    }

    function isKYCValid(address user) public view returns (bool) {
        Identity storage id = _identities[user];
        return id.status == KYCStatus.Verified && block.timestamp < id.expiresAt && id.screening == ScreeningStatus.Clear;
    }

    /// @notice Whether the last screening satisfies `institution`'s freshness policy.
    function isScreeningFresh(address user, address institution) public view returns (bool) {
        uint64 maxAge = freshnessPolicy[institution];
        if (maxAge == 0) return true;
        uint64 last = _identities[user].lastScreenedAt;
        return last != 0 && block.timestamp - last <= maxAge;
    }

    /// @notice Validity as seen by a specific institution (global validity + its freshness policy).
    function isKYCValidFor(address user, address institution) public view returns (bool) {
        return isKYCValid(user) && isScreeningFresh(user, institution);
    }

    function hasConsent(address user, address institution, uint8 scope) public view returns (bool) {
        Consent storage c = _consents[user][institution];
        return c.active && block.timestamp < c.expiresAt && (c.scopes & scope) == scope && hasRole(INSTITUTION_ROLE, institution);
    }

    /// @notice A customer's own full record (only the customer, providers, oracle and admin).
    function getIdentity(address user) external view returns (Identity memory) {
        if (
            msg.sender != user &&
            !hasRole(PROVIDER_ROLE, msg.sender) &&
            !hasRole(ORACLE_ROLE, msg.sender) &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) revert NotAuthorized();
        return _identities[user];
    }

    /// @notice Public, non-PII status (lets anyone see that an address is registered / pending).
    function statusOf(address user) external view returns (KYCStatus) {
        return _identities[user].status;
    }

    function getConsent(address user, address institution) external view returns (Consent memory) {
        return _consents[user][institution];
    }

    function getConsentedInstitutions(address user) external view returns (address[] memory) {
        return _consentedInstitutions[user];
    }

    function getAccessRequests(address user) external view returns (AccessRequest[] memory) {
        return _accessRequests[user];
    }

    function getAttributeKeys(address user) external view returns (bytes32[] memory) {
        return _attributeKeys[user];
    }

    function getAttributeCommitment(address user, bytes32 attrKey) external view returns (bytes32) {
        return _attributes[user][attrKey];
    }

    function subjectCount() external view returns (uint256) {
        return _subjects.length;
    }

    /// @notice Paginated list of registered addresses (used by providers' review queue and the oracle).
    function getSubjects(uint256 offset, uint256 limit) external view returns (address[] memory page) {
        uint256 n = _subjects.length;
        if (offset >= n) return new address[](0);
        uint256 end = offset + limit > n ? n : offset + limit;
        page = new address[](end - offset);
        for (uint256 i = offset; i < end; i++) page[i - offset] = _subjects[i];
    }
}
