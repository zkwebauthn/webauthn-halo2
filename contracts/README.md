## Quickstart

`forge build`
`forge test`

## Gas Benchmarks

```
[PASS] testCreation() (gas: 26649)
[PASS] testUserOpE2EFailure() (gas: 467146)
[PASS] testUserOpE2ESuccess() (gas: 516558)
```

| src/P256Account.sol:P256Account contract |                 |        |        |        |         |
| ---------------------------------------- | --------------- | ------ | ------ | ------ | ------- |
| Deployment Cost                          | Deployment Size |        |        |        |         |
| 1663310                                  | 8618            |        |        |        |         |
| Function Name                            | min             | avg    | median | max    | # calls |
| execute                                  | 21826           | 21826  | 21826  | 21826  | 1       |
| getNonce                                 | 8143            | 8143   | 8143   | 8143   | 1       |
| initialize                               | 118202          | 118202 | 118202 | 118202 | 3       |
| publicKey                                | 3277            | 3277   | 3277   | 3277   | 1       |
| validateUserOp                           | 399221          | 399477 | 399477 | 399733 | 2       |

| src/P256AccountFactory.sol:P256AccountFactory contract |                 |        |        |        |         |
| ------------------------------------------------------ | --------------- | ------ | ------ | ------ | ------- |
| Deployment Cost                                        | Deployment Size |        |        |        |         |
| 2234339                                                | 11530           |        |        |        |         |
| Function Name                                          | min             | avg    | median | max    | # calls |
| createAccount                                          | 223055          | 223055 | 223055 | 223055 | 3       |
