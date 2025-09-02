[Not Paid]

## Conclusion

Lido's answer:<br>
"Intended precision loss, because it is used to get number of full requestsCount."

What I learn:

This statement reveals the core disagreement between us and the Lido team:

- **Our perspective (technical purity):** Any computational error leading to permanent loss of funds, no matter how minor, constitutes a vulnerability.
- **Their perspective (business logic):** The \*\*sole responsibility\*\* of this function is to calculate “how many full packages can be formed.” Regarding the remaining dust, they argue it falls outside this function's scope and is treated as “acceptable business loss” or “handled by other modules.”

**Conclusion:** We're caught in a debate over whether this is a Bug or a Feature. In Bug Bounties, as long as the project team can justify it as “Intended Behavior,” they have the right to reject the report.

## **Description**

**Severity:** Low (Precision loss in financial calculations leads to permanent loss of user funds "dust").

### Vulnerability Details

The `calcRequestAmounts` function in the `WithdrawalsBatchesQueue` library utilizes a "divide-before-multiply" pattern for its calculations, which is a known anti-pattern in Solidity that leads to precision loss with integer arithmetic.

Specifically, the function calculates `requestsCount` using integer division, which truncates any remainder. This imprecise `requestsCount` is then used to derive the `lastRequestAmount`. When the true remainder of `remainingAmount / maxRequestAmount` is a non-zero value that is less than `minRequestAmount`, the flawed calculation causes this remainder to be incorrectly discarded.

As a result, the sum of the amounts in the returned array is less than the original `remainingAmount` provided, leading to a permanent loss of the residual amount ("dust").

**Vulnerable Code:**`contracts/libraries/WithdrawalsBatchesQueue.sol:219-223`

```solidity
function calcRequestAmounts(
    uint256 minRequestAmount,
    uint256 maxRequestAmount,
    uint256 remainingAmount
) internal pure returns (uint256[] memory requestAmounts) {
    uint256 requestsCount = remainingAmount / maxRequestAmount; // <-- 1. Precision loss occurs here.
    // last request amount will be equal to zero when it's multiple requestAmount
    // when it's in the range [0, minRequestAmount) - it will not be included in the result
    uint256 lastRequestAmount = remainingAmount - requestsCount * maxRequestAmount; // <-- 2. Remainder is calculated with the imprecise count.
    if (lastRequestAmount >= minRequestAmount) { // <-- 3. Incorrectly calculated remainder may be discarded.
        requestsCount += 1;
    }
    // ...
}
```

**Impact**

This vulnerability leads to a direct and permanent loss of user funds. Although the amount lost in a single instance might be small (dust), the flaw exists in a core financial calculation library. This violates the fundamental principle that a protocol must not lose user assets due to calculation errors. Over time and across multiple operations, these small losses could accumulate. This issue undermines the integrity and reliability of the protocol's accounting.

**Suggested Remediation**

The calculation of the remainder should be performed using the modulo operator (`%`), which is the standard, precise, and gas-efficient method. This avoids the "divide-before-multiply" issue entirely.

**Recommendation:**

```diff
function calcRequestAmounts(
    uint256 minRequestAmount,
    uint256 maxRequestAmount,
    uint256 remainingAmount
) internal pure returns (uint256[] memory requestAmounts) {
-   uint256 requestsCount = remainingAmount / maxRequestAmount;
-   uint256 lastRequestAmount = remainingAmount - requestsCount * maxRequestAmount;
+   uint256 lastRequestAmount = remainingAmount % maxRequestAmount;
+   uint256 requestsCount = remainingAmount / maxRequestAmount;

    if (lastRequestAmount >= minRequestAmount) {
        requestsCount += 1;
    }
    // ... rest of the function ...
}
```

A more comprehensive fix should also re-evaluate how dust amounts (remainders less than `minRequestAmount`) are handled to ensure they are never lost, for example, by bundling them with the last valid request if possible.

## **Proof of Concept**

### **PoC Explanation**

The following Foundry test provides a concrete example of the fund loss. It calls the `calcRequestAmounts` function with parameters specifically chosen to trigger the precision loss. The test then sums the values in the array returned by the function and asserts that this sum is less than the original amount, proving that a portion of the funds (`50 ether` in this case) has been permanently lost.

**PoC Code (`test/PrecisionLoss.t.sol`)**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console} from "../lib/forge-std/src/Test.sol";
import {WithdrawalsBatchesQueue} from "../contracts/libraries/WithdrawalsBatchesQueue.sol";

/// @title PoC for Precision Loss in WithdrawalsBatchesQueue
/// @author Yu-Wei Chang / Immunefi-Id: Jacky2ha
/// @notice This test demonstrates that the `calcRequestAmounts` function can lead to a permanent
///         loss of funds ("dust") due to a precision loss issue from integer division.
contract PrecisionLoss_PoC_Test is Test {
    /// @notice This test proves that a remainder smaller than `minRequestAmount` is discarded,
    ///         causing the total calculated amount to be less than the original amount.
    function test_PoC_PrecisionLoss_Causes_FundLoss() public pure {
        // --- 1. SETUP ---
        // We choose parameters where the remainder of the division is positive
        // but smaller than the minimum allowed request amount.
        uint256 maxRequestAmount = 1000 ether;
        uint256 minRequestAmount = 100 ether;
        // This amount will result in a remainder of 50 ether (2050 % 1000 = 50).
        uint256 remainingAmount = 2050 ether;

        console.log("--- Test Case: Potential Fund Loss ---");
        console.log("Original Amount to Process: %s wei", remainingAmount);
        console.log("Max Request Amount: %s wei", maxRequestAmount);
        console.log("Min Request Amount: %s wei", minRequestAmount);

        // --- 2. EXECUTION ---
        // Call the vulnerable function.
        uint256[] memory requestAmounts = WithdrawalsBatchesQueue
            .calcRequestAmounts(
                minRequestAmount,
                maxRequestAmount,
                remainingAmount
            );

        // --- 3. ASSERTION ---
        // Sum the amounts returned by the function.
        uint256 totalCalculatedAmount = 0;
        for (uint i = 0; i < requestAmounts.length; i++) {
            totalCalculatedAmount += requestAmounts[i];
        }

        console.log("Function returned %s batches.", requestAmounts.length);
        console.log("Total Calculated Amount: %s wei", totalCalculatedAmount);

        uint256 fundsLost = remainingAmount - totalCalculatedAmount;
        console.log("Funds Lost (Dust): %s wei", fundsLost);

        // CORE PROOF: The total amount calculated by the function is less than the original amount.
        // This assertion proves that some funds were permanently lost in the calculation.
        assertLt(
            totalCalculatedAmount,
            remainingAmount,
            "Total calculated amount should be less than the original amount"
        );

        // We can be more specific: assert that exactly 50 ether were lost.
        assertEq(
            fundsLost,
            50 ether,
            "The amount of lost funds should be exactly 50 ether"
        );
    }
}
```
