# GetInfo

## Windbg

1. 查看SSDT Failure

```shell
1: kd> dd KeServiceDescriptorTable //这个符号所在的地址
fffff802`0c236740  0c178640 fffff802 00000000 00000000 //通过KiSystemCall64获取的 fffff802`0c236740
fffff802`0c236750  000001b9 00000000 0c17940c fffff802
fffff802`0c236760  00000000 00000000 00000000 00000000
fffff802`0c236770  00000000 00000000 00000000 00000000
fffff802`0c236780  00000000 00000000 00000000 00000000
fffff802`0c236790  00aba955 00000000 f1bf5410 00007ffe
fffff802`0c2367a0  1ed32a20 ffffe001 1ed31c60 ffffe001
fffff802`0c2367b0  00000000 00000000 00000000 00000000

1: kd> dd fffff8020c178640 //此处应该为SSDT表
fffff802`0c178640  fde8d244 fdec2100 022702c2 039a6c00
fffff802`0c178650  011ade00 fe481900 01186d05 01263c06
fffff802`0c178660  0117ac05 0200f701 01e8d600 010d52c0
fffff802`0c178670  020b7c40 010ddc00 0123dd00 01199500
fffff802`0c178680  018eea01 01232201 017acb40 018dee02
fffff802`0c178690  01b256c0 01ae1f40 012a1101 012aa702
fffff802`0c1786a0  00ff6f02 019e8901 0200b301 02186505
fffff802`0c1786b0  013ed900 02033683 00fed300 0391b8c0

```

2. 获取KiSystemCall64

```c++
1: kd> rdmsr c0000082
msr[c0000082] = fffff802`0bfc7fc0

1: kd> u fffff802`0bfc7fc0 L50
nt!KiSystemCall64:
fffff802`0bfc7fc0 0f01f8          swapgs
fffff802`0bfc7fc3 654889242510000000 mov   qword ptr gs:[10h],rsp //保存context
fffff802`0bfc7fcc 65488b2425a8010000 mov   rsp,qword ptr gs:[1A8h]  //切换堆栈
fffff802`0bfc7fd5 6a2b            push    2Bh
fffff802`0bfc7fd7 65ff342510000000 push    qword ptr gs:[10h]
fffff802`0bfc7fdf 4153            push    r11
fffff802`0bfc7fe1 6a33            push    33h
fffff802`0bfc7fe3 51              push    rcx
fffff802`0bfc7fe4 498bca          mov     rcx,r10
fffff802`0bfc7fe7 4883ec08        sub     rsp,8
fffff802`0bfc7feb 55              push    rbp
fffff802`0bfc7fec 4881ec58010000  sub     rsp,158h
fffff802`0bfc7ff3 488dac2480000000 lea     rbp,[rsp+80h]
fffff802`0bfc7ffb 48899dc0000000  mov     qword ptr [rbp+0C0h],rbx
fffff802`0bfc8002 4889bdc8000000  mov     qword ptr [rbp+0C8h],rdi
fffff802`0bfc8009 4889b5d0000000  mov     qword ptr [rbp+0D0h],rsi
fffff802`0bfc8010 c645ab02        mov     byte ptr [rbp-55h],2
fffff802`0bfc8014 65488b1c2588010000 mov   rbx,qword ptr gs:[188h]
fffff802`0bfc801d 0f0d8b90000000  prefetchw [rbx+90h]
fffff802`0bfc8024 0fae5dac        stmxcsr dword ptr [rbp-54h]
fffff802`0bfc8028 650fae142580010000 ldmxcsr dword ptr gs:[180h]
fffff802`0bfc8031 807b0300        cmp     byte ptr [rbx+3],0
fffff802`0bfc8035 66c785800000000000 mov   word ptr [rbp+80h],0
fffff802`0bfc803e 0f849a000000    je      nt!KiSystemCall64+0x11e (fffff802`0bfc80de) 
fffff802`0bfc8044 488945b0        mov     qword ptr [rbp-50h],rax
fffff802`0bfc8048 48894db8        mov     qword ptr [rbp-48h],rcx
fffff802`0bfc804c 488955c0        mov     qword ptr [rbp-40h],rdx
fffff802`0bfc8050 f6430303        test    byte ptr [rbx+3],3
fffff802`0bfc8054 4c8945c8        mov     qword ptr [rbp-38h],r8
fffff802`0bfc8058 4c894dd0        mov     qword ptr [rbp-30h],r9
fffff802`0bfc805c 7405            je      nt!KiSystemCall64+0xa3 (fffff802`0bfc8063)
fffff802`0bfc805e e89d60ffff      call    nt!KiSaveDebugRegisterState (fffff802`0bfbe100)
fffff802`0bfc8063 f6430304        test    byte ptr [rbx+3],4
fffff802`0bfc8067 740e            je      nt!KiSystemCall64+0xb7 (fffff802`0bfc8077)
fffff802`0bfc8069 fb              sti
fffff802`0bfc806a 488bcc          mov     rcx,rsp
fffff802`0bfc806d e8a2855600      call    nt!PsPicoSystemCallDispatch (fffff802`0c530614)
fffff802`0bfc8072 e9f4010000      jmp     nt!KiSystemServiceExit (fffff802`0bfc826b)
fffff802`0bfc8077 f6430380        test    byte ptr [rbx+3],80h
fffff802`0bfc807b 7442            je      nt!KiSystemCall64+0xff (fffff802`0bfc80bf)
fffff802`0bfc807d b9020100c0      mov     ecx,0C0000102h
fffff802`0bfc8082 0f32            rdmsr
fffff802`0bfc8084 48c1e220        shl     rdx,20h
fffff802`0bfc8088 480bc2          or      rax,rdx
fffff802`0bfc808b 483983f0000000  cmp     qword ptr [rbx+0F0h],rax
fffff802`0bfc8092 742b            je      nt!KiSystemCall64+0xff (fffff802`0bfc80bf)
fffff802`0bfc8094 48398300020000  cmp     qword ptr [rbx+200h],rax
fffff802`0bfc809b 7422            je      nt!KiSystemCall64+0xff (fffff802`0bfc80bf)
fffff802`0bfc809d 488b93f0010000  mov     rdx,qword ptr [rbx+1F0h]
fffff802`0bfc80a4 0fba6b7408      bts     dword ptr [rbx+74h],8
fffff802`0bfc80a9 66ff8be6010000  dec     word ptr [rbx+1E6h]
fffff802`0bfc80b0 48898280000000  mov     qword ptr [rdx+80h],rax
fffff802`0bfc80b7 fb              sti
fffff802`0bfc80b8 e8c30d0000      call    nt!KiUmsCallEntry (fffff802`0bfc8e80)
fffff802`0bfc80bd eb0b            jmp     nt!KiSystemCall64+0x10a (fffff802`0bfc80ca)
fffff802`0bfc80bf f6430340        test    byte ptr [rbx+3],40h
fffff802`0bfc80c3 7405            je      nt!KiSystemCall64+0x10a (fffff802`0bfc80ca)
fffff802`0bfc80c5 0fba6b7410      bts     dword ptr [rbx+74h],10h
fffff802`0bfc80ca 488b45b0        mov     rax,qword ptr [rbp-50h]
fffff802`0bfc80ce 488b4db8        mov     rcx,qword ptr [rbp-48h]
fffff802`0bfc80d2 488b55c0        mov     rdx,qword ptr [rbp-40h]
fffff802`0bfc80d6 4c8b45c8        mov     r8,qword ptr [rbp-38h]
fffff802`0bfc80da 4c8b4dd0        mov     r9,qword ptr [rbp-30h]
fffff802`0bfc80de fb              sti
fffff802`0bfc80df 48898b88000000  mov     qword ptr [rbx+88h],rcx
fffff802`0bfc80e6 898380000000    mov     dword ptr [rbx+80h],eax
fffff802`0bfc80ec 0f1f4000        nop     dword ptr [rax]

nt!KiSystemServiceStart:
fffff802`0bfc80f0 4889a390000000  mov     qword ptr [rbx+90h],rsp
fffff802`0bfc80f7 8bf8            mov     edi,eax
fffff802`0bfc80f9 c1ef07          shr     edi,7
fffff802`0bfc80fc 83e720          and     edi,20h
fffff802`0bfc80ff 25ff0f0000      and     eax,0FFFh

nt!KiSystemServiceRepeat:
fffff802`0bfc8104 4c8d1535e62600  lea     r10,[nt!KeServiceDescriptorTable (fffff802`0c236740)] //搜索4c8d lea指令
fffff802`0bfc810b 4c8d1deee52600  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff802`0c236700)]
fffff802`0bfc8112 f7437840000000  test    dword ptr [rbx+78h],40h
fffff802`0bfc8119 4d0f45d3        cmovne  r10,r11
fffff802`0bfc811d 423b441710      cmp     eax,dword ptr [rdi+r10+10h]
fffff802`0bfc8122 0f83ef020000    jae     nt!KiSystemServiceExit+0x1ac (fffff802`0bfc8417)
fffff802`0bfc8128 4e8b1417        mov     r10,qword ptr [rdi+r10]
fffff802`0bfc812c 4d631c82        movsxd  r11,dword ptr [r10+rax*4]

//得到KeServiceDescriptorTable的内存地址
1: kd> dd fffff802`0c236740
fffff802`0c236740  0c178640 fffff802 00000000 00000000 //第一个地址为KiServiceTable
fffff802`0c236750  000001b9 00000000 0c17940c fffff802
fffff802`0c236760  00000000 00000000 00000000 00000000
fffff802`0c236770  00000000 00000000 00000000 00000000
fffff802`0c236780  00000000 00000000 00000000 00000000
fffff802`0c236790  00aba955 00000000 f1bf5410 00007ffe
fffff802`0c2367a0  1ed32a20 ffffe001 1ed31c60 ffffe001
fffff802`0c2367b0  00000000 00000000 00000000 00000000

//KiSerciceTable
1: kd> dd fffff8020c178640
fffff802`0c178640  fde8d244 fdec2100 022702c2 039a6c00
fffff802`0c178650  011ade00 fe481900 01186d05 01263c06
fffff802`0c178660  0117ac05 0200f701 01e8d600 010d52c0
fffff802`0c178670  020b7c40 010ddc00 0123dd00 01199500
fffff802`0c178680  018eea01 01232201 017acb40 018dee02
fffff802`0c178690  01b256c0 01ae1f40 012a1101 012aa702
fffff802`0c1786a0  00ff6f02 019e8901 0200b301 02186505
fffff802`0c1786b0  013ed900 02033683 00fed300 0391b8c0

1: kd> u fffff8020c178640 L50
nt!KiServiceTable:
fffff802`0c178640 44d2e8          shr     al,cl
fffff802`0c178643 fd              std
fffff802`0c178644 0021            add     byte ptr [rcx],ah
fffff802`0c178646 ec              in      al,dx
fffff802`0c178647 fd              std
fffff802`0c178648 c20227          ret     2702h
fffff802`0c17864b 0200            add     al,byte ptr [rax]
fffff802`0c17864d 6c              ins     byte ptr [rdi],dx
fffff802`0c17864e 9a              ???
fffff802`0c17864f 0300            add     eax,dword ptr [rax]
fffff802`0c178651 de1a            ficomp  word ptr [rdx]
fffff802`0c178653 0100            add     dword ptr [rax],eax
fffff802`0c178655 1948fe          sbb     dword ptr [rax-2],ecx
fffff802`0c178658 056d180106      add     eax,601186Dh
fffff802`0c17865d 3c26            cmp     al,26h
fffff802`0c17865f 0105ac170101    add     dword ptr [fffff802`0d189e11],eax
fffff802`0c178665 f7000200d6e8    test    dword ptr [rax],0E8D60002h
fffff802`0c17866b 01c0            add     eax,eax
fffff802`0c17866d 52              push    rdx
fffff802`0c17866e 0d01407c0b      or      eax,0B7C4001h
fffff802`0c178673 0200            add     al,byte ptr [rax]
fffff802`0c178675 dc0d0100dd23    fmul    qword ptr [fffff802`2ff4867c]
fffff802`0c17867b 0100            add     dword ptr [rax],eax
fffff802`0c17867d 95              xchg    eax,ebp
fffff802`0c17867e 1901            sbb     dword ptr [rcx],eax
fffff802`0c178680 01ea            add     edx,ebp
fffff802`0c178682 8e01            mov     es,word ptr [rcx]
fffff802`0c178684 0122            add     dword ptr [rdx],esp
fffff802`0c178686 2301            and     eax,dword ptr [rcx]
fffff802`0c178688 40cb            retf
fffff802`0c17868a 7a01            jp      nt!KiServiceTable+0x4d (fffff802`0c17868d)
fffff802`0c17868c 02ee            add     ch,dh
fffff802`0c17868e 8d01            lea     eax,[rcx]
fffff802`0c178690 c056b201        rcl     byte ptr [rsi-4Eh],1
    
//获取KeAddSystemServiceTable
nt!KeAddSystemServiceTable:
fffff802`0c3fbe44 48895c2408      mov     qword ptr [rsp+8],rbx
fffff802`0c3fbe49 837c242801      cmp     dword ptr [rsp+28h],1
fffff802`0c3fbe4e 458bd8          mov     r11d,r8d
fffff802`0c3fbe51 4c8bd1          mov     r10,rcx
fffff802`0c3fbe54 757f            jne     nt!KeAddSystemServiceTable+0x91 (fffff802`0c3fbed5)
fffff802`0c3fbe56 48833d02a9e3ff00 cmp     qword ptr [nt!KeServiceDescriptorTable+0x20 (fffff802`0c236760)],0
fffff802`0c3fbe5e 7575            jne     nt!KeAddSystemServiceTable+0x91 (fffff802`0c3fbed5)
fffff802`0c3fbe60 48833db8a8e3ff00 cmp     qword ptr [nt!KeServiceDescriptorTableShadow+0x20 (fffff802`0c236720)],0
fffff802`0c3fbe68 756b            jne     nt!KeAddSystemServiceTable+0x91 (fffff802`0c3fbed5)
fffff802`0c3fbe6a 4c890dc7a8e3ff  mov     qword ptr [nt!KeServiceDescriptorTableShadow+0x38 (fffff802`0c236738)],r9
fffff802`0c3fbe71 488d05a8a8e3ff  lea     rax,[nt!KeServiceDescriptorTableShadow+0x20 (fffff802`0c236720)]
fffff802`0c3fbe78 4533c9          xor     r9d,r9d
fffff802`0c3fbe7b 448905aea8e3ff  mov     dword ptr [nt!KeServiceDescriptorTableShadow+0x30 (fffff802`0c236730)],r8d
fffff802`0c3fbe82 48890d97a8e3ff  mov     qword ptr [nt!KeServiceDescriptorTableShadow+0x20 (fffff802`0c236720)],rcx
fffff802`0c3fbe89 448d0408        lea     r8d,[rax+rcx]
fffff802`0c3fbe8d 4585db          test    r11d,r11d
fffff802`0c3fbe90 7426            je      nt!KeAddSystemServiceTable+0x74 (fffff802`0c3fbeb8)
fffff802`0c3fbe92 488bd9          mov     rbx,rcx
fffff802`0c3fbe95 486313          movsxd  rdx,dword ptr [rbx]
fffff802`0c3fbe98 41ffc1          inc     r9d
fffff802`0c3fbe9b 488bc2          mov     rax,rdx
fffff802`0c3fbe9e 488d5b04        lea     rbx,[rbx+4]
fffff802`0c3fbea2 48c1f804        sar     rax,4
fffff802`0c3fbea6 428b0c10        mov     ecx,dword ptr [rax+r10]
fffff802`0c3fbeaa 03ca            add     ecx,edx
fffff802`0c3fbeac 4433c1          xor     r8d,ecx
fffff802`0c3fbeaf 450fafc1        imul    r8d,r9d
fffff802`0c3fbeb3 453bcb          cmp     r9d,r11d
fffff802`0c3fbeb6 72dd            jb      nt!KeAddSystemServiceTable+0x51 (fffff802`0c3fbe95)
fffff802`0c3fbeb8 8b0dfac4d8ff    mov     ecx,dword ptr [nt!KiTableInformation (fffff802`0c1883b8)]
fffff802`0c3fbebe 428d1441        lea     edx,[rcx+r8*2]
fffff802`0c3fbec2 8915f0c4d8ff    mov     dword ptr [nt!KiTableInformation (fffff802`0c1883b8)],edx
fffff802`0c3fbec8 f0830c2400      lock or dword ptr [rsp],0
fffff802`0c3fbecd b001            mov     al,1
fffff802`0c3fbecf 488b5c2408      mov     rbx,qword ptr [rsp+8]
fffff802`0c3fbed4 c3              ret
fffff802`0c3fbed5 32c0            xor     al,al
fffff802`0c3fbed7 ebf6            jmp     nt!KeAddSystemServiceTable+0x8b (fffff802`0c3fbecf)
fffff802`0c3fbed9 cc              int     3
fffff802`0c3fbeda cc              int     3
fffff802`0c3fbedb cc              int     3

```

