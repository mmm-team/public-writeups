void state0(void) {
  code *UNRECOVERED_JUMPTABLE;
  
  index = 0;
  state = 1;
                    // WARNING: Could not recover jumptable at 0x004005e8. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}

void state1(void) {
  code *UNRECOVERED_JUMPTABLE;
  
  if (index < 0x20) {
    state = 2;
  }
  else {
    state = 3;
  }
                    // WARNING: Could not recover jumptable at 0x00400644. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}

void state2(char *param_1) {
  code *UNRECOVERED_JUMPTABLE;
  
  state = 1;
  switch(index) {
  case 0:
    correct = (correct & 1 & *(int *)param_1 == 0x43434553) != 0;
    break;
  case 4:
    correct = (correct & 1 & *(int *)(param_1 + index) == 0x357b4e4f) != 0;
    break;
  case 8:
    correct = (correct & 1 & *(int *)(param_1 + index) == 0x336b3468) != 0;
    break;
  case 0xc:
    correct = (correct & 1 & *(int *)(param_1 + index) == 0x5f74315f) != 0;
  case 0x1c:
    correct = (correct & 1 &
              *(int *)(param_1 + index) - *(int *)(param_1 + (long)index + -4) == 0x47cb363b) != 0;
    break;
  case 0x10:
    correct = (correct & 1 &
              *(int *)(param_1 + index) + *(int *)(param_1 + (long)index + -4) == -0x6b2c5e2c) != 0;
    break;
  case 0x14:
    correct = (correct & 1 &
              *(int *)(param_1 + index) + *(int *)(param_1 + (long)index + -4) == -0x626b6223) != 0;
    break;
  case 0x18:
    correct = (correct & 1 &
              *(int *)(param_1 + index) + *(int *)(param_1 + (long)index + -4) == -0x62629d6b) != 0;
  }
                    // WARNING: Could not recover jumptable at 0x00400c3c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}

void main(int argc,char **argv) {
  code *UNRECOVERED_JUMPTABLE;
  code *apcStack_60 [4];
  char *pcStack_40;
  undefined4 uStack_34;
  undefined *local_30;
  code *local_28;
  char **local_20;
  int local_18;
  undefined4 local_14;
  
  local_30 = &stack0xfffffffffffffff0;
  local_14 = 0;
  local_20 = argv;
  if (argc != 2) {
    local_18 = argc;
    puts("Incorrect");
    local_28 = (code *)0x400e54;
                    // WARNING: Could not recover jumptable at 0x00400e70. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(local_14);
    return;
  }
  local_28 = (code *)&DAT_00400e24;
  pcStack_40 = argv[1];
  state = 0;
  local_18 = 2;
  do {
    switch(state) {
    case 0:
    case 1:
    case 2:
      apcStack_60[1] = state1;
      apcStack_60[0] = state0;
      apcStack_60[2] = state2;
      (*apcStack_60[state])(pcStack_40);
      index += 4;
      break;
    case 3:
      if ((correct & 1) == 0) {
        state = 5;
      }
      else {
        state = 4;
      }
      break;
    case 4:
      uStack_34 = 1;
LAB_00400dc4:
                    // WARNING: Could not recover jumptable at 0x00400dd8. Too many branches
                    // WARNING: Treating indirect jump as call
      (*local_28)(uStack_34);
      return;
    case 5:
      uStack_34 = 0;
      goto LAB_00400dc4;
    }
  } while( true );
}

