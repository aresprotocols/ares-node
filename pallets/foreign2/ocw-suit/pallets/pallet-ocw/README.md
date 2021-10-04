## Introduction
* Obtain the price data of ares through the off-chain working machine and submit it to the chain.
* Only validators have the opportunity to submit a quotation.
* If `NeedVerifierCheck = true` then author_insertKey ares required.

## Configuration
* The `UnsignedInterval` parameter is used to set the interval block from this transaction to the next transaction submission.
* The `UnsignedPriority` parameter is used to set the priority of submission under the chain.
* A specific implementation object of the `ValidatorSet` trait needs to be provided to obtain validator-related data, which is usually implemented using session-related modules.
* `PriceVecMaxSize` is a u32 constant that determines the depth of the prices pool. The setting of this constant will affect the calculation result of the final average.
* `MaxCountOfPerRequest` is a u32 constant that determines the maximum number of requests per time.
* `NeedVerifierCheck` is used to determine whether to enable block author matching check. If it is set to true, the keystore of ares must be set to be consistent with the verifier.
* `FractionLengthNum` is used to control determine precision. The maximum value is 6. 
* `CalculationKind` is used to decide which way of average calculation. `1` = `average`, `2` = `median`

## Price Request management
* TODO::

## How to add price on 