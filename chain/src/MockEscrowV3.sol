// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @notice Faithful-to-v2 mock of the NEW (v3) BullEscrow (0xd961cA37...).
/// The v3 escrow is NOT source-verified; this mock is the v2 source
/// (verbatim, verified on Sourcify chain 4663) PLUS the one documented v3
/// delta that matters here: createDeal is 3-arg and verifies an EIP-712
/// seller Consent on-chain (domain BullEscrow v3, type Consent with the
/// 10 fields the new SDK/MCP check: buyer, seller, sellerPayout,
/// buyerReceive, sellToken, sellAmount, payToken, payAmount, deadline,
/// validUntil). Everything else (fundPayment exact-value + buyer-only,
/// fundTokens seller-only, atomic settle, fee quote binding buyer+params)
/// is copied verbatim from the v2 source.
/// The PoC's claim is about the CLIENT (SDK fund() not binding steps to
/// the dealId passed), not about this mock's internals.
contract MockEscrowV3 {
    enum Status { None, Open, Settled, Cancelled }

    struct Deal {
        address buyer;
        address seller;
        address sellToken;
        uint256 sellAmount;
        address payToken;
        uint256 payAmount;
        uint64 deadline;
        bool buyerFunded;
        bool sellerFunded;
        Status status;
        address sellerPayout;
        address buyerReceive;
        uint16 feeBps;
    }

    struct DealParams {
        address seller;
        address sellerPayout;
        address buyerReceive;
        address sellToken;
        uint256 sellAmount;
        address payToken;
        uint256 payAmount;
        uint64 deadline;
    }

    struct Quote {
        uint16 feeBps;
        uint64 expiry;
        bytes sig;
    }

    uint16 public constant MAX_FEE_BPS = 250;
    address public immutable treasury;
    address public immutable feeSigner;

    uint256 public nextId = 1;
    mapping(uint256 => Deal) internal _deals;

    uint256 private _lock = 1;

    event DealCreated(uint256 indexed id, address indexed buyer, address indexed seller, uint16 feeBps);
    event Funded(uint256 indexed id, address indexed by);
    event Settled(uint256 indexed id, uint256 fee);
    event Cancelled(uint256 indexed id, address indexed by);

    error NotParty();
    error BadState();
    error BadInput();
    error WrongAmount();
    error TransferFailed();
    error Reentrancy();
    error BadQuote();
    error BadConsent();

    bytes32 private constant CONSENT_TYPEHASH = keccak256(
        "Consent(address buyer,address seller,address sellerPayout,address buyerReceive,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline,uint64 validUntil)"
    );

    /// @dev Domain separator is computed dynamically (not an immutable):
    /// the PoC etches this bytecode at the production escrow address, and
    /// an immutable baked at deploy time would name the deploy address.

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(address _treasury, address _feeSigner) {
        if (_treasury == address(0) || _feeSigner == address(0)) revert BadInput();
        treasury = _treasury;
        feeSigner = _feeSigner;
    }

    function _domainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("BullEscrow")),
                keccak256(bytes("3")),
                block.chainid,
                address(this)
            )
        );
    }

    function deals(uint256 id) external view returns (Deal memory) {
        return _deals[id];
    }

    /// @notice v3 createDeal: DealParams + seller Consent signature + fee Quote.
    /// The Consent binds buyer, seller, sellerPayout, buyerReceive,
    /// sellToken, sellAmount, payToken, payAmount, deadline, validUntil.
    function createDeal(DealParams calldata p, bytes calldata sellerSig, Quote calldata q, uint64 validUntil) external returns (uint256 id) {
        if (p.seller == address(0) || p.seller == msg.sender) revert BadInput();
        if (p.sellToken == address(0) || p.sellToken == p.payToken) revert BadInput();
        if (p.sellAmount == 0 || p.payAmount == 0) revert BadInput();
        if (p.deadline <= block.timestamp) revert BadInput();
        if (validUntil < block.timestamp) revert BadConsent();
        if (p.sellerPayout == address(this) || p.buyerReceive == address(this)) revert BadInput();
        if (q.feeBps > MAX_FEE_BPS || block.timestamp > q.expiry) revert BadQuote();
        if (_quoteSigner(p, q) != feeSigner) revert BadQuote();
        if (_consentSigner(p, validUntil, sellerSig) != p.seller) revert BadConsent();

        id = nextId++;
        Deal storage d = _deals[id];
        d.buyer = msg.sender;
        d.seller = p.seller;
        d.sellToken = p.sellToken;
        d.sellAmount = p.sellAmount;
        d.payToken = p.payToken;
        d.payAmount = p.payAmount;
        d.deadline = p.deadline;
        d.status = Status.Open;
        d.sellerPayout = p.sellerPayout == address(0) ? p.seller : p.sellerPayout;
        d.buyerReceive = p.buyerReceive == address(0) ? msg.sender : p.buyerReceive;
        d.feeBps = q.feeBps;
        emit DealCreated(id, msg.sender, p.seller, q.feeBps);
    }

    function fundPayment(uint256 id) external payable nonReentrant {
        Deal storage d = _deals[id];
        if (d.status != Status.Open || block.timestamp > d.deadline) revert BadState();
        if (msg.sender != d.buyer) revert NotParty();
        if (d.buyerFunded) revert BadState();

        d.buyerFunded = true;
        if (d.payToken == address(0)) {
            if (msg.value != d.payAmount) revert WrongAmount();
        } else {
            if (msg.value != 0) revert WrongAmount();
            _pull(d.payToken, msg.sender, d.payAmount);
        }
        emit Funded(id, msg.sender);
        _maybeSettle(id, d);
    }

    function fundTokens(uint256 id) external nonReentrant {
        Deal storage d = _deals[id];
        if (d.status != Status.Open || block.timestamp > d.deadline) revert BadState();
        if (msg.sender != d.seller) revert NotParty();
        if (d.sellerFunded) revert BadState();

        d.sellerFunded = true;
        _pull(d.sellToken, msg.sender, d.sellAmount);
        emit Funded(id, msg.sender);
        _maybeSettle(id, d);
    }

    function cancel(uint256 id) external nonReentrant {
        Deal storage d = _deals[id];
        if (d.status != Status.Open) revert BadState();
        if (msg.sender != d.buyer && msg.sender != d.seller && block.timestamp <= d.deadline) revert NotParty();

        d.status = Status.Cancelled;
        bool bf = d.buyerFunded;
        bool sf = d.sellerFunded;
        d.buyerFunded = false;
        d.sellerFunded = false;

        if (bf) _send(d.payToken, d.buyer, d.payAmount);
        if (sf) _send(d.sellToken, d.seller, d.sellAmount);
        emit Cancelled(id, msg.sender);
    }

    function _maybeSettle(uint256 id, Deal storage d) private {
        if (!(d.buyerFunded && d.sellerFunded)) return;
        d.status = Status.Settled;

        uint256 fee = (d.payAmount * d.feeBps) / 10_000;
        _send(d.sellToken, d.buyerReceive, d.sellAmount);
        _send(d.payToken, d.sellerPayout, d.payAmount - fee);
        if (fee > 0) _send(d.payToken, treasury, fee);
        emit Settled(id, fee);
    }

    function _consentSigner(DealParams calldata p, uint64 validUntil, bytes calldata sig) private view returns (address) {
        bytes32 structHash = keccak256(
            abi.encode(
                CONSENT_TYPEHASH,
                msg.sender,
                p.seller,
                p.sellerPayout,
                p.buyerReceive,
                p.sellToken,
                p.sellAmount,
                p.payToken,
                p.payAmount,
                p.deadline,
                validUntil
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        return _recover(digest, sig);
    }

    function _quoteHash(DealParams calldata p, uint16 feeBps, uint64 expiry) private view returns (bytes32) {
        DealParams memory m = p;
        bytes32 ph = keccak256(abi.encode(m));
        return keccak256(abi.encode(block.chainid, address(this), msg.sender, ph, feeBps, expiry));
    }

    function _quoteSigner(DealParams calldata p, Quote calldata q) private view returns (address) {
        bytes32 h = _quoteHash(p, q.feeBps, q.expiry);
        return _recover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h)), q.sig);
    }

    function _pull(address token, address from, uint256 amount) private {
        if (!IERC20(token).transferFrom(from, address(this), amount)) revert TransferFailed();
    }

    function _send(address token, address to, uint256 amount) private {
        if (token == address(0)) {
            (bool ok, ) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            if (!IERC20(token).transfer(to, amount)) revert TransferFailed();
        }
    }

    function _recover(bytes32 digest, bytes memory sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
