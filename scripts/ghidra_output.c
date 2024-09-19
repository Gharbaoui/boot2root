#include "out.h"



int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  func_0x00000000();
  frame_dummy();
  iVar1 = gcc2_compiled_();
  return iVar1;
}



void FUN_08048710(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



void __register_frame_info(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fprintf(FILE *__stream,char *__format,...)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * tmpfile(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * getenv(char *__name)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__sighandler_t signal(int __sig,__sighandler_t __handler)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fflush(FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void bcopy(void *__src,void *__dest,size_t __n)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void rewind(FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int system(char *__command)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __deregister_frame_info(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * fgets(char *__s,int __n,FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint sleep(uint __seconds)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __strtol_internal(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __libc_start_main(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

hostent * gethostbyname(char *__name)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void bzero(void *__s,size_t __n)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sscanf(char *__s,char *__format,...)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int connect(int __fd,sockaddr *__addr,socklen_t __len)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int dup(int __fd)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sprintf(char *__s,char *__format,...)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int socket(int __domain,int __type,int __protocol)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * cuserid(char *__s)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcpy(char *__dest,char *__src)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_4 [4];
  
  __libc_start_main(main,param_2,&stack0x00000004,_init,_fini,param_1,auStack_4);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void gcc2_compiled_(void)

{
  code *pcVar1;
  
  if (completed_4 == 0) {
    while (*(int *)p_3 != 0) {
      pcVar1 = *(code **)p_3;
      p_3 = p_3 + 4;
      (*pcVar1)();
    }
    __deregister_frame_info(&cie_0804b484);
    completed_4 = 1;
  }
  return;
}



void fini_dummy(void)

{
  return;
}



void frame_dummy(void)

{
  __register_frame_info(&cie_0804b484,object_11);
  return;
}



void init_dummy(void)

{
  return;
}



// WARNING: Unknown calling convention

int main(int argc,char **argv)

{
  undefined4 uVar1;
  int in_stack_00000004;
  undefined4 *in_stack_00000008;
  
  if (in_stack_00000004 == 1) {
    infile = stdin;
  }
  else {
    if (in_stack_00000004 != 2) {
      printf("Usage: %s [<input_file>]\n",*in_stack_00000008);
                    // WARNING: Subroutine does not return
      exit(8);
    }
    infile = (_IO_FILE *)fopen((char *)in_stack_00000008[1],"r");
    if ((FILE *)infile == (FILE *)0x0) {
      printf("%s: Error: Couldn\'t open %s\n",*in_stack_00000008,in_stack_00000008[1]);
                    // WARNING: Subroutine does not return
      exit(8);
    }
  }
  initialize_bomb(argv);
  printf("Welcome this is my little bomb !!!! You have 6 stages with\n");
  printf("only one life good luck !! Have a nice day!\n");
  uVar1 = read_line();
  phase_1(uVar1);
  phase_defused();
  printf("Phase 1 defused. How about the next one?\n");
  uVar1 = read_line();
  phase_2(uVar1);
  phase_defused();
  printf("That\'s number 2.  Keep going!\n");
  uVar1 = read_line();
  phase_3(uVar1);
  phase_defused();
  printf("Halfway there!\n");
  uVar1 = read_line();
  phase_4(uVar1);
  phase_defused();
  printf("So you got that one.  Try this one.\n");
  uVar1 = read_line();
  phase_5(uVar1);
  phase_defused();
  printf("Good work!  On to the next...\n");
  uVar1 = read_line();
  phase_6(uVar1);
  phase_defused();
  return 0;
}



void phase_1(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = strings_not_equal(param_1,"Public speaking is very easy.");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}



void phase_2(undefined4 param_1)

{
  int iVar1;
  int aiStack_20 [7];
  
  read_six_numbers(param_1,aiStack_20 + 1);
  if (aiStack_20[1] != 1) {
    explode_bomb();
  }
  iVar1 = 1;
  do {
    if (aiStack_20[iVar1 + 1] != (iVar1 + 1) * aiStack_20[iVar1]) {
      explode_bomb();
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  return;
}



void phase_3(char *param_1)

{
  int iVar1;
  char cVar2;
  undefined4 local_10;
  char local_9;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d %c %d",&local_10,&local_9,&local_8);
  if (iVar1 < 3) {
    explode_bomb();
  }
  switch(local_10) {
  case 0:
    cVar2 = 'q';
    if (local_8 != 0x309) {
      explode_bomb();
    }
    break;
  case 1:
    cVar2 = 'b';
    if (local_8 != 0xd6) {
      explode_bomb();
    }
    break;
  case 2:
    cVar2 = 'b';
    if (local_8 != 0x2f3) {
      explode_bomb();
    }
    break;
  case 3:
    cVar2 = 'k';
    if (local_8 != 0xfb) {
      explode_bomb();
    }
    break;
  case 4:
    cVar2 = 'o';
    if (local_8 != 0xa0) {
      explode_bomb();
    }
    break;
  case 5:
    cVar2 = 't';
    if (local_8 != 0x1ca) {
      explode_bomb();
    }
    break;
  case 6:
    cVar2 = 'v';
    if (local_8 != 0x30c) {
      explode_bomb();
    }
    break;
  case 7:
    cVar2 = 'b';
    if (local_8 != 0x20c) {
      explode_bomb();
    }
    break;
  default:
    cVar2 = 'x';
    explode_bomb();
  }
  if (cVar2 != local_9) {
    explode_bomb();
  }
  return;
}



int func4(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}



void phase_4(char *param_1)

{
  int iVar1;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d",&local_8);
  if ((iVar1 != 1) || (local_8 < 1)) {
    explode_bomb();
  }
  iVar1 = func4(local_8);
  if (iVar1 != 0x37) {
    explode_bomb();
  }
  return;
}



void phase_5(int param_1)

{
  int iVar1;
  undefined local_c [6];
  undefined local_6;
  
  iVar1 = string_length(param_1);
  if (iVar1 != 6) {
    explode_bomb();
  }
  iVar1 = 0;
  do {
    local_c[iVar1] = (&array_123)[(char)(*(byte *)(iVar1 + param_1) & 0xf)];
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  local_6 = 0;
  iVar1 = strings_not_equal(local_c,"giants");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}



// WARNING: Type propagation algorithm not settling

void phase_6(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined1 *local_38;
  int *local_34 [6];
  int local_1c [6];
  
  local_38 = node1;

  iVar4 = 0;
  do {
    iVar2 = 1;
    piVar3 = (int *)local_38;
    if (1 < local_1c[iVar4]) {
      do {
        piVar3 = (int *)piVar3[2];
        iVar2 = iVar2 + 1;
      } while (iVar2 < local_1c[iVar4]);
    }
    local_34[iVar4] = piVar3;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
  

  iVar4 = 1;
  piVar3 = local_34[0];
  do {
    piVar1 = local_34[iVar4];
    piVar3[2] = (int)piVar1;
    iVar4 = iVar4 + 1;
    piVar3 = piVar1;
  } while (iVar4 < 6);
  piVar1[2] = 0;
  iVar4 = 0;
  do {
    if (*local_34[0] < *(int *)local_34[0][2]) {
      explode_bomb();
    }
    local_34[0] = (int *)local_34[0][2];
    iVar4 = iVar4 + 1;
  } while (iVar4 < 5);
  return;
}



int fun7(int *param_1,int param_2)

{
  int iVar1;
  
  if (param_1 == (int *)0x0) {
    iVar1 = -1;
  }
  else if (param_2 < *param_1) {
    iVar1 = fun7(param_1[1],param_2);
    iVar1 = iVar1 * 2;
  }
  else if (param_2 == *param_1) {
    iVar1 = 0;
  }
  else {
    iVar1 = fun7(param_1[2],param_2);
    iVar1 = iVar1 * 2 + 1;
  }
  return iVar1;
}



void secret_phase(void)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = read_line();
  iVar2 = __strtol_internal(uVar1,0,10,0);
  if (1000 < iVar2 - 1U) {
    explode_bomb();
  }
  iVar2 = fun7(n1,iVar2);
  if (iVar2 != 7) {
    explode_bomb();
  }
  printf("Wow! You\'ve defused the secret stage!\n");
  phase_defused();
  return;
}



void sig_handler(void)

{
  printf("So you think you can stop the bomb with ctrl-c, do you?\n");
  sleep(3);
  printf("Well...");
  fflush(stdout);
  sleep(1);
  printf("OK. :-)\n");
                    // WARNING: Subroutine does not return
  exit(0x10);
}



void invalid_phase(undefined4 param_1)

{
  printf("Invalid phase%s\n",param_1);
                    // WARNING: Subroutine does not return
  exit(8);
}



void read_six_numbers(char *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = sscanf(param_1,"%d %d %d %d %d %d",param_2,param_2 + 4,param_2 + 8,param_2 + 0xc,
                 param_2 + 0x10,param_2 + 0x14);
  if (iVar1 < 6) {
    explode_bomb();
  }
  return;
}



int string_length(char *param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  cVar1 = *param_1;
  while (cVar1 != '\0') {
    param_1 = param_1 + 1;
    iVar2 = iVar2 + 1;
    cVar1 = *param_1;
  }
  return iVar2;
}



undefined4 strings_not_equal(char *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  iVar2 = string_length(param_1);
  iVar3 = string_length(param_2);
  if (iVar2 == iVar3) {
    cVar1 = *param_1;
    while (cVar1 != '\0') {
      if (*param_1 != *param_2) goto LAB_08049057;
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      cVar1 = *param_1;
    }
    uVar4 = 0;
  }
  else {
LAB_08049057:
    uVar4 = 1;
  }
  return uVar4;
}



int open_clientfd(char *param_1,ushort param_2)

{
  int __fd;
  hostent *phVar1;
  int iVar2;
  sockaddr local_14;
  
  __fd = socket(2,1,0);
  if (__fd < 0) {
    printf("Bad host (1).\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  phVar1 = gethostbyname(param_1);
  if (phVar1 == (hostent *)0x0) {
    printf("Bad host (2).\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  bzero(&local_14,0x10);
  local_14.sa_family = 2;
  bcopy(*phVar1->h_addr_list,local_14.sa_data + 2,phVar1->h_length);
  local_14.sa_data._0_2_ = param_2 >> 8 | param_2 << 8;
  iVar2 = connect(__fd,&local_14,0x10);
  if (iVar2 < 0) {
    printf("Bad host (3).\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  return __fd;
}



void initialize_bomb(void)

{
  signal(2,sig_handler);
  return;
}



undefined4 blank_line(char *param_1)

{
  char cVar1;
  
  cVar1 = *param_1;
  while( true ) {
    if (cVar1 == '\0') {
      return 1;
    }
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    if ((*(byte *)(__ctype_b + 1 + cVar1 * 2) & 0x20) == 0) break;
    cVar1 = *param_1;
  }
  return 0;
}



char * skip(void)

{
  char *pcVar1;
  int iVar2;
  
  do {
    pcVar1 = fgets(input_strings + num_input_strings * 0x50,0x50,(FILE *)infile);
    if (pcVar1 == (char *)0x0) {
      return (char *)0x0;
    }
    iVar2 = blank_line(pcVar1);
  } while (iVar2 != 0);
  return pcVar1;
}



undefined1 * read_line(void)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  uint uVar4;
  
  iVar2 = skip();
  if (iVar2 == 0) {
    if (infile != stdin) {
      pcVar3 = getenv("GRADE_BOMB");
      if (pcVar3 != (char *)0x0) {
                    // WARNING: Subroutine does not return
        exit(0);
      }
      infile = stdin;
      iVar2 = skip();
      if (iVar2 != 0) goto LAB_0804925f;
    }
    printf("Error: Premature EOF on stdin\n");
    explode_bomb();
  }
LAB_0804925f:
  uVar4 = 0xffffffff;
  pcVar3 = input_strings + num_input_strings * 0x50;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  if (~uVar4 == 0x50) {
    printf("Error: Input line too long\n");
    explode_bomb();
  }
  iVar2 = num_input_strings * 0x50;
  *(undefined *)(~uVar4 + 0x804b67e + iVar2) = 0;
  num_input_strings = num_input_strings + 1;
  return input_strings + iVar2;
}



void send_msg(int param_1)

{
  int iVar1;
  int iVar2;
  FILE *__stream;
  char *pcVar3;
  int iVar4;
  undefined4 local_54;
  undefined2 local_50;
  undefined local_4e;
  
  iVar1 = dup(0);
  if (iVar1 == -1) {
    printf("ERROR: dup(0) error\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  iVar2 = close(0);
  if (iVar2 == -1) {
    printf("ERROR: close error\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  __stream = tmpfile();
  if (__stream == (FILE *)0x0) {
    printf("ERROR: tmpfile error\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  fprintf(__stream,"Subject: Bomb notification\n");
  fprintf(__stream,"\n");
  pcVar3 = cuserid((char *)0x0);
  if (pcVar3 == (char *)0x0) {
    local_54 = 0x6f626f6e;
    local_50 = 0x7964;
    local_4e = 0;
  }
  else {
    strcpy((char *)&local_54,pcVar3);
  }
  pcVar3 = "exploded";
  if (param_1 != 0) {
    pcVar3 = "defused";
  }
  fprintf(__stream,"bomb-header:%s:%d:%s:%s:%d\n",lab_id,bomb_id,&local_54,pcVar3,num_input_strings)
  ;
  iVar2 = 0;
  if (0 < num_input_strings) {
    do {
      iVar4 = iVar2 * 0x50;
      iVar2 = iVar2 + 1;
      fprintf(__stream,"bomb-string:%s:%d:%s:%d:%s\n",lab_id,bomb_id,&local_54,iVar2,
              input_strings + iVar4);
    } while (iVar2 < num_input_strings);
  }
  rewind(__stream);
  sprintf(scratch,"%s %s@%s","/usr/sbin/sendmail -bm",&DAT_08049c53,"bluegill.cmcl.cs.cmu.edu");
  iVar2 = system(scratch);
  if (iVar2 != 0) {
    printf("ERROR: notification error\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  iVar2 = fclose(__stream);
  if (iVar2 != 0) {
    printf("ERROR: fclose(tmp) error\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  iVar2 = dup(iVar1);
  if (iVar2 != 0) {
    printf("ERROR: dup(tmpstdin) error\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  iVar1 = close(iVar1);
  if (iVar1 != 0) {
    printf("ERROR: close(tmpstdin)\n");
                    // WARNING: Subroutine does not return
    exit(8);
  }
  return;
}



void explode_bomb(void)

{
  printf("\nBOOM!!!\n");
  printf("The bomb has blown up.\n");
                    // WARNING: Subroutine does not return
  exit(8);
}



void phase_defused(void)

{
  int iVar1;
  undefined local_58 [4];
  undefined local_54 [80];
  
  if (num_input_strings == 6) {
    iVar1 = sscanf(input_strings + 0xf0,"%d %s",local_58,local_54);
    if (iVar1 == 2) {
      iVar1 = strings_not_equal(local_54,"austinpowers");
      if (iVar1 == 0) {
        printf("Curses, you\'ve found the secret phase!\n");
        printf("But finding it and solving it are quite different...\n");
        secret_phase();
      }
    }
    printf("Congratulations! You\'ve defused the bomb!\n");
  }
  return;
}



void gcc2_compiled_(void)

{
  code **ppcVar1;
  
  ppcVar1 = (code **)&__CTOR_LIST__;
  if (__CTOR_LIST__ != -1) {
    do {
      (**ppcVar1)();
      ppcVar1 = ppcVar1 + -1;
    } while (*ppcVar1 != (code *)0xffffffff);
  }
  return;
}



void init_dummy(void)

{
  return;
}



void _fini(void)

{
  gcc2_compiled_();
  return;
}



