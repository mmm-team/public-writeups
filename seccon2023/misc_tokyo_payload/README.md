# Tokyo Payload

The simple solidity contract provides the ability to jump anywhere (JUMPDEST) in the smart contract through the `tokyoPayload` function.
Each call to tokyoPayload resets the gas limit by calling `resetGasLimit`, so we need to call resetGasLimit and deletecall in the same call.
The basic strategy is as follows:

1. tokyoPayload
1. resetGasLimit
1. delegatecall

We did some fuzzing stuff to match the apporopriate stack fengsui with `cyclic`.

```solidity
    function tokyoPayload(uint256 x, uint256 y) public {
        require(x >= 0x40);
        resetGasLimit();
        assembly {
            calldatacopy(x, 0, calldatasize())
        }
        function()[] memory funcs; // lol
        uint256 z = y;
        funcs[z]();
    }

    function load(uint256 i) public pure returns (uint256 a, uint256 b, uint256 c) {
        assembly {
            a := calldataload(i)
            b := calldataload(add(i, 0x20))
            c := calldataload(add(i, 0x40))
        }
    }

    function createArray(uint256 length) public pure returns (uint256[] memory) {
        return new uint256[](length);
    }

    function resetGasLimit() public {
        uint256[] memory arr;
        gasLimit = arr.length;
    }

    function delegatecall(address addr) public {
        require(msg.sender == address(0xCAFE));
        (bool success,) = addr.delegatecall{gas: gasLimit & 0xFFFF}("");
        require(success);
    }
```

- Solve script in https://gist.github.com/junomonster/dea9a13e9473e636a41e01b39ba7c95b
