## 📂 Case Studies: Lido Dual Governance Vulnerability Research

This section contains a selection of my findings from a deep dive into the Lido Dual Governance and Escrow mechanism. Each report includes a detailed breakdown, a runnable Proof-of-Concept, and my personal reflections on the outcome.

### 1. [Critical] Malicious Governance Configuration Leading to Permanent Fund Lock

- **Vulnerability:** The `Escrow.sol` contract's RageQuit process placed excessive trust in the configuration of the external `WithdrawalQueue.sol`. By maliciously setting `maxStETHWithdrawalAmount` to a near-zero value, a compromised governance could permanently trap all user funds within the `Escrow` contract.
- **Impact:** **Permanent freezing of all user funds** participating in the RageQuit, with no recovery mechanism.
- **Root Cause:** A functional deadlock caused by a reverting external call that was not properly handled.
- **Lesson Learned:** This report highlighted the critical importance of defensive programming in smart contracts, especially when interacting with external contracts whose state can be modified by privileged roles. Even though the scenario relied on a compromised governance (which was deemed out-of-scope), it demonstrated my ability to trace complex interactions and identify critical failure points. This experience reinforced the principle that protocols should not only be secure in their own logic but also resilient against the potential misconfiguration or malicious action of their dependencies.

### 2. [Critical] Precision Loss Exploitation Leading to Permanent Fund Lock

- **Vulnerability:** A logic flaw in how the `requestNextWithdrawalsBatch` function handled "dust" amounts (small remainders from integer division) allowed an attacker to prematurely and permanently close the withdrawal queue.
- **Impact:** **Permanent freezing of a portion of user funds**. An unprivileged attacker could deposit a crafted amount to ensure some of another user's funds would become irrecoverable dust.
- **Root Cause:** Improper state management when handling residual balances that were below a minimum threshold but greater than zero.
- **Lesson Learned:** This finding was a valuable lesson in the nuances of smart contract accounting. The root cause was identified as a "1-2 wei corner case," a known issue related to stETH's share calculation mechanism. While my report presented a novel way to weaponize this known issue to cause fund loss, it underscored the rule that vulnerabilities stemming from a documented and accepted root cause are often out of scope. It was a masterclass in understanding the difference between finding a _new flaw_ versus finding a _new exploit for an old, accepted flaw_.

### 3. [Critical] Protocol Insolvency via Re-Entrancy-Like Double Spend

- **Vulnerability:** A state management flaw in the `Escrow` contract's accounting library (`AssetsAccounting.sol`) allowed for a "double spend" of a user's `unstETH` NFT. An attacker could lock an NFT, withdraw it, and still have the protocol account for it as if it were finalized, creating a permanent deficit.
- **Impact:** **Protocol Insolvency**. The attack created a quantifiable "bad debt" in the protocol's ledger, socialized across all honest users.
- **Root Cause:** Improper state transition logic. The status of a withdrawn asset was not cleared correctly, leaving a dangling state record that could be triggered a second time.
- **Lesson Learned:** This report was a deep dive into state management and accounting integrity. While I correctly identified a valid state management flaw, the Lido team demonstrated that their internal accounting logic in another part of the contract (`accountUnstETHUnlock`) effectively mitigated the double-spend risk. My key takeaway was that assessing the _true impact_ of a vulnerability is as critical as finding the vulnerability itself. A technical flaw without a real, exploitable economic consequence is not a critical vulnerability. This experience sharpened my ability to evaluate the full context and internal mitigating controls of a protocol.

### 4. [Medium] Griefing Attack by Abusing Lock Timer Reset

- **Vulnerability:** An attacker could maliciously call the `accountUnstETHLock` function with the victim's address but an empty input array. Due to a lack of input validation, this action would unconditionally reset the victim's asset lock timer to the current block timestamp without locking any new assets.
- **Impact:** **Temporary loss of funds availability (Griefing)**. This attack could repeatedly prevent a targeted user from withdrawing their funds once their lock period had expired, causing disruption and potential opportunity costs for the victim.
- **Root Cause:** A combination of an uninitialized local variable and a failure to validate for empty input arrays, leading to an unconditional state change (`lastAssetsLockTimestamp` update) even when no core action (locking assets) was performed.
- **Lesson Learned:** This investigation taught me a valuable lesson in the importance of business risk assessment in bug bounties. While I successfully demonstrated a technically valid griefing attack, the Lido team classified it as an "Acceptable Risk." Their reasoning was that the attack had a non-trivial gas cost for the attacker but yielded no financial profit, only the temporary inconvenience of a single user. This experience highlighted that the severity of a bug is not just about its technical feasibility, but a practical calculation of its impact, the attacker's incentive, and the cost to exploit versus the damage inflicted. It's a crucial reminder that project teams often view security through a lens of pragmatic risk management.

### 5. [Low] Potential Loss of Funds Due to Precision Loss in `calcRequestAmounts`

- **Vulnerability:** The `calcRequestAmounts` function used a "divide-before-multiply" pattern, a known anti-pattern in Solidity for integer arithmetic. This led to precision loss, causing any remainder "dust" that was smaller than the minimum request amount to be permanently discarded during calculations.
- **Impact:** **Permanent loss of user funds (dust)**. Although the individual loss was minimal, it represented a flaw in a core financial library that should, in principle, never lose user assets due to calculation errors.
- **Root Cause:** The use of integer division (`/`) to determine `requestsCount` before calculating the remainder, instead of using the precise modulo (`%`) operator first.
- **Lesson Learned:** This finding led to a fascinating debate on the definition of a "bug" versus an "intended feature." From a technical purist's viewpoint, any non-zero loss of funds from a calculation is a flaw. However, the Lido team clarified that the function's sole purpose was to calculate the number of _full_ batches, and the leftover dust was considered an acceptable and "intended precision loss" from a business logic perspective. This experience was a masterclass in understanding that in the world of bug bounties, if a project can reasonably justify a behavior as intended for their specific business logic, they have the final say, even if it contradicts common best practices.

---
