
undefined8 FUN_00106155(int param_1,long param_2)

{
  byte bVar1;
  int __fd;
  int __fd_00;
  int iVar2;
  ssize_t sVar3;
  long in_FS_OFFSET;
  int local_f68;
  int local_f64;
  int local_f60;
  int local_f5c;
  ulong local_f50;
  size_t local_f48;
  ulong local_f40;
  long local_f38;
  undefined8 local_f30;
  undefined8 local_f28;
  undefined8 local_f18 [160];
  undefined local_a18 [2568];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 3) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  __fd = open(*(char **)(param_2 + 8),0);
  if (__fd < 0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  __fd_00 = open(*(char **)(param_2 + 0x10),0x42,0x1a4);
  if (__fd_00 < 0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  DAT_001090a0 = msgget(0,0x3b6);
  if (DAT_001090a0 < 0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  DAT_001090a4 = msgget(0,0x3b6);
  if (DAT_001090a4 < 0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  for (local_f68 = 0; local_f68 < 4; local_f68 = local_f68 + 1) {
    pthread_create((pthread_t *)(&DAT_001090c0 + (long)local_f68 * 8),(pthread_attr_t *)0x0,
                   FUN_0010603f,&DAT_00109020 + (long)local_f68 * 0x18);
  }
  do {
    local_f40 = read(__fd,local_f18,0x500);
    if (local_f40 % 10 != 0) {
      bVar1 = 10 - ((char)local_f40 + ((char)(local_f40 / 10 << 2) + (char)(local_f40 / 10)) * -2) ;
      for (local_f64 = 0; local_f64 < (int)(uint)bVar1; local_f64 = local_f64 + 1) {
        *(byte *)((long)local_f18 + (long)local_f64 + local_f40) = bVar1;
      }
      local_f40 = local_f40 + bVar1;
    }
    local_f48 = 0;
    for (local_f50 = 0; local_f50 < local_f40; local_f50 = local_f50 + 10) {
      for (local_f60 = 1; local_f60 < 5; local_f60 = local_f60 + 1) {
        local_f38 = (long)local_f60;
        local_f28 = *(undefined8 *)((long)local_f18 + local_f50 + 8);
        local_f30 = *(undefined8 *)((long)local_f18 + local_f50);
        iVar2 = msgsnd(DAT_001090a0,&local_f38,0x10,0);
        if (iVar2 != 0) {
          perror("msgsnd-m");
        }
      }
      for (local_f5c = 1; local_f5c < 5; local_f5c = local_f5c + 1) {
        sVar3 = msgrcv(DAT_001090a4,&local_f38,0x10,(long)local_f5c,0);
        if (sVar3 < 0) {
          perror("msgrcv-m");
        }
        memcpy(local_a18 + (long)((local_f5c + -1) * 5) + local_f48,&local_f30,5);
      }
      local_f48 = local_f48 + 0x14;
    }
    write(__fd_00,local_a18,local_f48);
  } while (0x4ff < local_f40);
  iVar2 = msgctl(DAT_001090a0,0,(msqid_ds *)0x0);
  if (iVar2 == -1) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar2 = msgctl(DAT_001090a4,0,(msqid_ds *)0x0);
  if (iVar2 == -1) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  close(__fd);
  close(__fd_00);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

