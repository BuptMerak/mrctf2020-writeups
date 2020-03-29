# SimpleReveal

本题主要考察对 solidity 和 web3 的应用。

## 解法一

```solidity
pragma solidity>=0.4.22;

contract reveal {

    private string flag="some_string_here";

}
```

根据原合约，可以看到 flag 应该在合约的前几个变量槽中，因此可以通过 `web3.eth.getStorageAt("合约地址", 0)` 获取存储的变量，从而解码得到flag。

## 解法二

Etherscan 上可以看到创建合约信息，其中可以看到 flag 。
