
======================================================================
Extracting sub_7FF6BD25F820
======================================================================
sub_7FF6BD25F820 proc near              ; CODE XREF: sub_7FF6BD25A2A0+78D↑p
                                        ; DATA XREF: .pdata:00007FF6C6FA0DF4↓o

var_2E0         = qword ptr -2E0h
var_2D8         = qword ptr -2D8h
var_2D0         = qword ptr -2D0h
var_2C8         = qword ptr -2C8h
var_2C0         = dword ptr -2C0h
var_2B0         = byte ptr -2B0h
var_2AF         = byte ptr -2AFh
var_2AE         = byte ptr -2AEh
var_2AD         = byte ptr -2ADh
var_2AC         = dword ptr -2ACh
var_2A8         = qword ptr -2A8h
var_2A0         = dword ptr -2A0h
var_298         = qword ptr -298h
var_290         = qword ptr -290h
var_288         = qword ptr -288h
var_278         = qword ptr -278h
var_270         = dword ptr -270h
var_268         = qword ptr -268h
var_260         = qword ptr -260h
var_258         = qword ptr -258h
var_250         = qword ptr -250h
var_248         = qword ptr -248h
var_240         = qword ptr -240h
var_238         = qword ptr -238h
var_230         = qword ptr -230h
var_220         = qword ptr -220h
var_218         = qword ptr -218h
var_210         = xmmword ptr -210h
var_200         = xmmword ptr -200h
var_1F0         = byte ptr -1F0h
var_1E8         = qword ptr -1E8h
var_1E0         = qword ptr -1E0h
var_1D0         = byte ptr -1D0h
var_1C8         = qword ptr -1C8h
var_1B8         = qword ptr -1B8h
var_1A0         = byte ptr -1A0h
Src             = qword ptr -110h
var_108         = dword ptr -108h
var_100         = qword ptr -100h
var_E0          = qword ptr -0E0h
var_D8          = qword ptr -0D8h
var_D0          = xmmword ptr -0D0h
var_C0          = qword ptr -0C0h
var_B8          = qword ptr -0B8h
var_B0          = xmmword ptr -0B0h
var_A0          = qword ptr -0A0h
var_98          = qword ptr -98h
var_90          = word ptr -90h
var_8E          = byte ptr -8Eh
var_88          = qword ptr -88h
var_80          = xmmword ptr -80h
var_70          = xmmword ptr -70h
var_60          = word ptr -60h
var_58          = qword ptr -58h
var_50          = qword ptr -50h
var_40          = qword ptr -40h
arg_18          = qword ptr  28h
arg_20          = qword ptr  30h

; __unwind { // __GSHandlerCheck_EH4
                mov     [rsp-8+arg_18], rbx
                push    rbp
                push    rsi
                push    rdi
                push    r12
                push    r13
                push    r14
                push    r15
                lea     rbp, [rsp-1D0h]
                sub     rsp, 2D0h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+200h+var_40], rax
                movzx   edi, r9b
                mov     [rsp+300h+var_298], r8
                mov     rsi, rdx
                mov     [rbp+200h+var_260], rdx
                mov     r15, rcx
                mov     r14, [rbp+200h+arg_20]
                mov     [rbp+200h+var_238], r14
                mov     r13, [rcx+50h]
                test    r13, r13
                jnz     short loc_7FF6BD25F8B2
                add     rcx, 0E0h
                call    sub_7FF6BAAAFAD0
                mov     r13, rax
                test    rax, rax
                jnz     short loc_7FF6BD25F8B2
                cmp     cs:byte_7FF6C6B68418, 6
                jb      loc_7FF6BD25FAF4
                lea     rdx, off_7FF6C3BDA350 ; "ReceivedBunch: Object == nullptr"
                lea     rcx, byte_7FF6C6B68418
                call    sub_7FF6BA751C70
                xor     al, al
                jmp     loc_7FF6BD2601F5
; ---------------------------------------------------------------------------

loc_7FF6BD25F8B2:                       ; CODE XREF: sub_7FF6BD25F820+55↑j
                                        ; sub_7FF6BD25F820+69↑j
                mov     rax, [r15+58h]
                mov     rbx, [rax+78h]
                mov     rax, [rax+88h]
                mov     [rbp+200h+var_248], rax
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax+4B0h]
                movzx   r12d, al
                mov     [rsp+300h+var_2AD], al
                mov     rcx, cs:qword_7FF6C6B68608
                cmp     dword ptr [rcx], 0
                jle     short loc_7FF6BD25F8EE
                test    al, al
                mov     [rsp+300h+var_2AE], 1
                jz      short loc_7FF6BD25F8F3

loc_7FF6BD25F8EE:                       ; CODE XREF: sub_7FF6BD25F820+C3↑j
                mov     [rsp+300h+var_2AE], 0

loc_7FF6BD25F8F3:                       ; CODE XREF: sub_7FF6BD25F820+CC↑j
                mov     eax, [rbx+5B8h]
                mov     [rsp+300h+var_2AC], eax
                mov     rdx, [r15+48h]
                mov     rcx, [rbx+210h]
                call    sub_7FF6BA967400
                mov     [rbp+200h+var_258], rax
                test    rax, rax
                jnz     short loc_7FF6BD25F977
                cmp     cs:byte_7FF6C6B68418, 2
                jb      loc_7FF6BD25FAF4
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rsp+300h+var_2A8]
                mov     rcx, r13
                call    sub_7FF6BAA98740
                nop
                cmp     dword ptr [rax+8], 0
                jz      short loc_7FF6BD25F942
                mov     r12, [rax]
                jmp     short loc_7FF6BD25F949
; ---------------------------------------------------------------------------

loc_7FF6BD25F942:                       ; CODE XREF: sub_7FF6BD25F820+11B↑j
                lea     r12, pwszOutputURL

loc_7FF6BD25F949:                       ; CODE XREF: sub_7FF6BD25F820+120↑j
                mov     r8, r12
                lea     rdx, off_7FF6C3BDA3B8 ; "ReceivedBunch: ClassCache == nullptr: %"...
                lea     rcx, byte_7FF6C6B68418
                call    sub_7FF6BA751C70
                nop
                mov     rcx, [rsp+300h+var_2A8]
                test    rcx, rcx
                jz      short loc_7FF6BD25F970
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD25F970:                       ; CODE XREF: sub_7FF6BD25F820+148↑j
                xor     al, al
                jmp     loc_7FF6BD2601F5
; ---------------------------------------------------------------------------

loc_7FF6BD25F977:                       ; CODE XREF: sub_7FF6BD25F820+F4↑j
                mov     rax, [r15+28h]
                mov     [rbp+200h+var_268], rax
                mov     [rsp+300h+var_2AF], 0
                mov     rax, [r15+38h]
                mov     rax, [rax]
                mov     [rbp+200h+var_240], rax
                test    dil, dil
                jz      loc_7FF6BD25FB05
                test    r12b, r12b
                jz      short loc_7FF6BD25F9FE
                cmp     cs:byte_7FF6C6B68418, 2
                jb      loc_7FF6BD25FAF4
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rsp+300h+var_2A8]
                mov     rcx, r13
                call    sub_7FF6BAA98740
                nop
                cmp     dword ptr [rax+8], 0
                jz      short loc_7FF6BD25F9C9
                mov     r12, [rax]
                jmp     short loc_7FF6BD25F9D0
; ---------------------------------------------------------------------------

loc_7FF6BD25F9C9:                       ; CODE XREF: sub_7FF6BD25F820+1A2↑j
                lea     r12, pwszOutputURL

loc_7FF6BD25F9D0:                       ; CODE XREF: sub_7FF6BD25F820+1A7↑j
                mov     r8, r12
                lea     rdx, off_7FF6C3BDA438 ; "Server received RepLayout properties: %"...
                lea     rcx, byte_7FF6C6B68418
                call    sub_7FF6BA751C70
                nop
                mov     rcx, [rsp+300h+var_2A8]
                test    rcx, rcx
                jz      short loc_7FF6BD25F9F7
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD25F9F7:                       ; CODE XREF: sub_7FF6BD25F820+1CF↑j
                xor     al, al
                jmp     loc_7FF6BD2601F5
; ---------------------------------------------------------------------------

loc_7FF6BD25F9FE:                       ; CODE XREF: sub_7FF6BD25F820+17B↑j
                mov     eax, [r15+14h]
                test    al, 8
                jnz     short loc_7FF6BD25FA33
                or      eax, 8
                mov     [r15+14h], eax
                mov     rcx, [r15+50h]
                test    rcx, rcx
                jnz     short loc_7FF6BD25FA2A
                lea     rcx, [r15+0E0h]
                call    sub_7FF6BAAAFAD0
                mov     rcx, rax
                test    rax, rax
                jz      short loc_7FF6BD25FA33

loc_7FF6BD25FA2A:                       ; CODE XREF: sub_7FF6BD25F820+1F4↑j
                mov     rax, [rcx]
                call    qword ptr [rax+2A8h]

loc_7FF6BD25FA33:                       ; CODE XREF: sub_7FF6BD25F820+1E4↑j
                                        ; sub_7FF6BD25F820+208↑j
                mov     rax, [rbx]
                mov     rdx, r13
                mov     rcx, rbx
                call    qword ptr [rax+518h]
                xor     edi, edi
                mov     edx, edi
                test    al, al
                setnz   dl
                mov     [rsp+300h+var_2B0], dil
                mov     rax, [rsp+300h+var_298]
                mov     eax, [rax]
                mov     ecx, edx
                or      ecx, 2
                test    al, 40h
                cmovz   ecx, edx
                mov     r9, [r15+38h]
                mov     [rsp+300h+var_2C0], ecx
                lea     rax, [rsp+300h+var_2AF]
                mov     [rsp+300h+var_2C8], rax
                lea     rax, [rsp+300h+var_2B0]
                mov     [rsp+300h+var_2D0], rax
                mov     [rsp+300h+var_2D8], rsi
                mov     [rsp+300h+var_2E0], r13
                mov     r9, [r9]
                mov     r8, [r15+48h]
                mov     rdx, [r15+60h]
                mov     rcx, [rbp+200h+var_268]
                call    sub_7FF6BD814A40
                test    al, al
                jnz     short loc_7FF6BD25FAFB
                cmp     cs:byte_7FF6C6B68438, 2
                jb      short loc_7FF6BD25FAF4
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rsp+300h+var_2A8]
                mov     rcx, r13
                call    sub_7FF6BAA98740
                nop
                cmp     [rax+8], edi
                jz      short loc_7FF6BD25FAC6
                mov     r12, [rax]
                jmp     short loc_7FF6BD25FACD
; ---------------------------------------------------------------------------

loc_7FF6BD25FAC6:                       ; CODE XREF: sub_7FF6BD25F820+29F↑j
                lea     r12, pwszOutputURL

loc_7FF6BD25FACD:                       ; CODE XREF: sub_7FF6BD25F820+2A4↑j
                mov     r8, r12
                lea     rdx, off_7FF6C3BDA4B8 ; "RepLayout->ReceiveProperties FAILED: %s"
                lea     rcx, byte_7FF6C6B68438
                call    sub_7FF6BA751C70
                nop
                mov     rcx, [rsp+300h+var_2A8]
                test    rcx, rcx
                jz      short loc_7FF6BD25FAF4
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD25FAF4:                       ; CODE XREF: sub_7FF6BD25F820+72↑j
                                        ; sub_7FF6BD25F820+FD↑j ...
                xor     al, al
                jmp     loc_7FF6BD2601F5
; ---------------------------------------------------------------------------

loc_7FF6BD25FAFB:                       ; CODE XREF: sub_7FF6BD25F820+27D↑j
                movzx   eax, [rsp+300h+var_2B0]
                or      [r14], al
                jmp     short loc_7FF6BD25FB07
; ---------------------------------------------------------------------------

loc_7FF6BD25FB05:                       ; CODE XREF: sub_7FF6BD25F820+172↑j
                xor     edi, edi

loc_7FF6BD25FB07:                       ; CODE XREF: sub_7FF6BD25F820+2E3↑j
                mov     rdx, [r15+48h]
                mov     rcx, [r15+60h]
                call    sub_7FF6BD254AD0
                mov     r12, rax
                mov     [rbp+200h+var_230], rax
                xor     r9d, r9d
                xor     r8d, r8d
                mov     rdx, [rsi+0B0h]
                lea     rcx, [rbp+200h+var_1A0]
                call    sub_7FF6BA94FEC0
                nop
;   try {
                mov     [rsp+300h+var_290], rdi
                lea     rax, off_7FF6C3BD9798
                mov     [rbp+200h+var_220], rax
                mov     [rbp+200h+var_218], rbx
                xorps   xmm0, xmm0
                movdqa  [rbp+200h+var_210], xmm0
                xorps   xmm1, xmm1
                movdqa  [rbp+200h+var_200], xmm1
                mov     [rbp+200h+var_1F0], 0
                mov     [rbp+200h+var_1E8], rdi
                mov     [rbp+200h+var_1E0], rdi
                lea     rax, [rbp+200h+var_1A0]
                mov     [rsp+300h+var_2D0], rax
                lea     rax, [rsp+300h+var_290]
                mov     [rsp+300h+var_2D8], rax
                mov     rbx, [rbp+200h+var_260]
                mov     [rsp+300h+var_2E0], rbx
                mov     r9, r12
                mov     r8, [rbp+200h+var_258]
                mov     rdx, r13
                mov     rcx, [r15+60h]
;   } // starts at 7FF6BD25FB32
;   try {
                call    sub_7FF6BD25DC60
                mov     esi, 0FFFFFFFFh
                test    al, al
                jz      loc_7FF6BD26015F
                lea     r12, pwszOutputURL

loc_7FF6BD25FBA5:                       ; CODE XREF: sub_7FF6BD25F820+939↓j
                test    byte ptr [rbx+29h], 2
                jnz     loc_7FF6BD2603CB
                mov     rbx, [rsp+300h+var_290]
                test    rbx, rbx
                jnz     short loc_7FF6BD25FC0E
                cmp     cs:byte_7FF6C6B68418, 3
                jb      loc_7FF6BD260127
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rbp+200h+var_1C8]
                mov     rcx, r13
                call    sub_7FF6BAA98740
                nop
;   } // starts at 7FF6BD25FB8C
;   try {
                cmp     [rax+8], ebx
                jz      short loc_7FF6BD25FBE3
                mov     r8, [rax]
                jmp     short loc_7FF6BD25FBE6
; ---------------------------------------------------------------------------

loc_7FF6BD25FBE3:                       ; CODE XREF: sub_7FF6BD25F820+3BC↑j
                mov     r8, r12

loc_7FF6BD25FBE6:                       ; CODE XREF: sub_7FF6BD25F820+3C1↑j
                lea     rdx, off_7FF6C3BDA5A0 ; "ReceivedBunch: FieldCache == nullptr: %"...
                lea     rcx, byte_7FF6C6B68418
                call    sub_7FF6BA751C70
                nop
;   } // starts at 7FF6BD25FBD9
;   try {
                mov     rcx, [rbp+200h+var_1C8]
                test    rcx, rcx
                jz      short loc_7FF6BD25FC09
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD25FBFA

loc_7FF6BD25FC09:                       ; CODE XREF: sub_7FF6BD25F820+3E1↑j
;   try {
                jmp     loc_7FF6BD260127
; ---------------------------------------------------------------------------

loc_7FF6BD25FC0E:                       ; CODE XREF: sub_7FF6BD25F820+397↑j
                cmp     byte ptr [rbx+10h], 0
                jz      loc_7FF6BD25FCA9
                cmp     cs:byte_7FF6C6B68418, 6
                jb      loc_7FF6BD260127
                lea     rdx, [rbp+200h+var_1D0]
                mov     rcx, rbx
                call    sub_7FF6BA967EE0
                lea     rdx, [rsp+300h+var_288]
                mov     rcx, rax
                call    sub_7FF6BA83CFA0
                nop
;   } // starts at 7FF6BD25FC09
;   try {
                cmp     dword ptr [rax+8], 0
                jz      short loc_7FF6BD25FC4A
                mov     rbx, [rax]
                jmp     short loc_7FF6BD25FC4D
; ---------------------------------------------------------------------------

loc_7FF6BD25FC4A:                       ; CODE XREF: sub_7FF6BD25F820+423↑j
                mov     rbx, r12

loc_7FF6BD25FC4D:                       ; CODE XREF: sub_7FF6BD25F820+428↑j
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rbp+200h+var_1B8]
                mov     rcx, r13
                call    sub_7FF6BAA98740
                nop
;   } // starts at 7FF6BD25FC3F
;   try {
                cmp     dword ptr [rax+8], 0
                jz      short loc_7FF6BD25FC6B
                mov     r8, [rax]
                jmp     short loc_7FF6BD25FC6E
; ---------------------------------------------------------------------------

loc_7FF6BD25FC6B:                       ; CODE XREF: sub_7FF6BD25F820+444↑j
                mov     r8, r12

loc_7FF6BD25FC6E:                       ; CODE XREF: sub_7FF6BD25F820+449↑j
                mov     r9, rbx
                lea     rdx, off_7FF6C3BDA618 ; "ReceivedBunch: FieldCache->bIncompatibl"...
                lea     rcx, byte_7FF6C6B68418
                call    sub_7FF6BA751C70
                nop
;   } // starts at 7FF6BD25FC60
;   try {
                mov     rcx, [rbp+200h+var_1B8]
                test    rcx, rcx
                jz      short loc_7FF6BD25FC94
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD25FC85

loc_7FF6BD25FC94:                       ; CODE XREF: sub_7FF6BD25F820+46C↑j
;   try {
                mov     rcx, [rsp+300h+var_288]
                test    rcx, rcx
                jz      short loc_7FF6BD25FCA4
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD25FC94

loc_7FF6BD25FCA4:                       ; CODE XREF: sub_7FF6BD25F820+47C↑j
;   try {
                jmp     loc_7FF6BD260127
; ---------------------------------------------------------------------------

loc_7FF6BD25FCA9:                       ; CODE XREF: sub_7FF6BD25F820+3F2↑j
                movzx   edx, byte ptr [rbx]
                and     dl, 1
                jnz     short loc_7FF6BD25FCCB
                mov     rdi, [rbx]
                test    rdi, rdi
                jz      short loc_7FF6BD25FCC9
                mov     rax, [rdi+8]
                mov     ecx, [rax+10h]
                shr     rcx, 14h
                test    cl, 1
                jnz     short loc_7FF6BD25FCCB

loc_7FF6BD25FCC9:                       ; CODE XREF: sub_7FF6BD25F820+497↑j
                xor     edi, edi

loc_7FF6BD25FCCB:                       ; CODE XREF: sub_7FF6BD25F820+48F↑j
                                        ; sub_7FF6BD25F820+4A7↑j
                test    rdi, rdi
                jz      loc_7FF6BD25FE8E
                cmp     [rsp+300h+var_2AD], 0
                jnz     loc_7FF6BD26021F
                mov     eax, [r15+14h]
                test    al, 8
                jnz     short loc_7FF6BD25FD14
                or      eax, 8
                mov     [r15+14h], eax
                mov     rcx, [r15+50h]
                test    rcx, rcx
                jnz     short loc_7FF6BD25FD0B
                lea     rcx, [r15+0E0h]
                call    sub_7FF6BAAAFAD0
                mov     rcx, rax
                test    rax, rax
                jz      short loc_7FF6BD25FD14

loc_7FF6BD25FD0B:                       ; CODE XREF: sub_7FF6BD25F820+4D5↑j
                mov     rax, [rcx]
                call    qword ptr [rax+2A8h]

loc_7FF6BD25FD14:                       ; CODE XREF: sub_7FF6BD25F820+4C5↑j
                                        ; sub_7FF6BD25F820+4E9↑j
                xor     eax, eax
                mov     [rbp+200h+var_E0], rax
                xorps   xmm0, xmm0
                movdqa  [rbp+200h+var_D0], xmm0
                xorps   xmm1, xmm1
                movdqa  [rbp+200h+var_B0], xmm1
                mov     [rbp+200h+var_98], rax
                mov     [rbp+200h+var_90], ax
                mov     [rbp+200h+var_8E], al
                mov     [rbp+200h+var_88], rax
                movdqa  [rbp+200h+var_80], xmm0
                movdqa  [rbp+200h+var_70], xmm1
                mov     ecx, 0FFFFh
                mov     [rbp+200h+var_60], cx
                mov     [rbp+200h+var_58], rax
                mov     [rbp+200h+var_50], rax
;   } // starts at 7FF6BD25FCA4
;   try {
                mov     rax, [rbp+200h+var_248]
                mov     [rbp+200h+var_C0], rax
                lea     rax, [rbp+200h+var_1A0]
                mov     [rbp+200h+var_D8], rax
                lea     rax, [rbp+200h+var_220]
                mov     [rbp+200h+var_A0], rax
                mov     rax, [r15+58h]
                mov     [rbp+200h+var_B8], rax
                movzx   ecx, byte ptr [rax+0F0h]
                and     cl, 1
                mov     byte ptr [rbp+200h+var_90], cl
                mov     [rbp+200h+var_88], r13
                mov     r9, rdi
                lea     r8, [rbp+200h+var_E0]
                mov     rdx, [rbp+200h+var_240]
                mov     rcx, [rbp+200h+var_268]
                call    sub_7FF6BD814620
                test    al, al
                jnz     short loc_7FF6BD25FDF3
                mov     byte ptr [rbx+10h], 1
;   } // starts at 7FF6BD25FD78
;   try {
                mov     rcx, [rbp+200h+var_58]
                test    rcx, rcx
                jz      short loc_7FF6BD25FDEC
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD25FDDA

loc_7FF6BD25FDEC:                       ; CODE XREF: sub_7FF6BD25F820+5C4↑j
;   try {
                xor     edi, edi
                jmp     loc_7FF6BD260127
; ---------------------------------------------------------------------------

loc_7FF6BD25FDF3:                       ; CODE XREF: sub_7FF6BD25F820+5B4↑j
                cmp     byte ptr [rbp+200h+var_98+3], 0
                jz      short loc_7FF6BD25FE00
                mov     byte ptr [r14], 1

loc_7FF6BD25FE00:                       ; CODE XREF: sub_7FF6BD25F820+5DA↑j
                cmp     byte ptr [rbp+200h+var_98+4], 0
                jz      short loc_7FF6BD25FE0E
                mov     [rsp+300h+var_2AF], 1

loc_7FF6BD25FE0E:                       ; CODE XREF: sub_7FF6BD25F820+5E7↑j
                cmp     cs:byte_7FF6C6B68478, 5
                jb      short loc_7FF6BD25FE75
                mov     rbx, r12
                cmp     dword ptr [rbp+200h+var_50], 0
                cmovnz  rbx, [rbp+200h+var_58]
                mov     rax, [r13+18h]
                mov     [rbp+200h+var_250], rax
                lea     rdx, [rsp+300h+var_2A8]
                lea     rcx, [rbp+200h+var_250]
;   } // starts at 7FF6BD25FDEC
;   try {
                call    sub_7FF6BA83CFA0
                nop
                mov     r8, r12
                cmp     [rsp+300h+var_2A0], 0
                cmovnz  r8, [rsp+300h+var_2A8]
                mov     r9, rbx
                lea     rdx, off_7FF6C3BDA758 ; " %s - %s"
                lea     rcx, byte_7FF6C6B68478
;   } // starts at 7FF6BD25FE3A
;   try {
                call    sub_7FF6BA751C70
                nop
                mov     rcx, [rsp+300h+var_2A8]
                test    rcx, rcx
                jz      short loc_7FF6BD25FE75
;   } // starts at 7FF6BD25FE5F
;   try {
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD25FE75:                       ; CODE XREF: sub_7FF6BD25F820+5F5↑j
                                        ; sub_7FF6BD25F820+64D↑j
                mov     rcx, [rbp+200h+var_58]
                test    rcx, rcx
                jz      short loc_7FF6BD25FE87
;   } // starts at 7FF6BD25FE6F
;   try {
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD25FE87:                       ; CODE XREF: sub_7FF6BD25F820+65F↑j
                xor     edi, edi
                jmp     loc_7FF6BD260127
; ---------------------------------------------------------------------------

loc_7FF6BD25FE8E:                       ; CODE XREF: sub_7FF6BD25F820+4AE↑j
                test    dl, dl
                jz      loc_7FF6BD260372
                mov     rdi, [rbx]
                and     rdi, 0FFFFFFFFFFFFFFFEh
                jz      loc_7FF6BD260372
;   } // starts at 7FF6BD25FE81
;   try {
                call    sub_7FF6BA92FC40
                mov     rdx, [rdi+10h]
                lea     r8, [rax+50h]
                movsxd  rax, dword ptr [r8+8]
                cmp     eax, [rdx+58h]
                jg      loc_7FF6BD260372
                mov     rcx, rax
                mov     rax, [rdx+50h]
                cmp     [rax+rcx*8], r8
                jnz     loc_7FF6BD260372
                mov     [rsp+300h+var_2B0], 0
                xor     edi, edi
                mov     [rbp+200h+var_E0], rdi
                mov     [rbp+200h+var_D8], rdi
                mov     [rbp+200h+var_C0], rdi
                mov     dword ptr [rbp+200h+var_B8], edi
                mov     dword ptr [rbp+200h+var_B8+4], 80h
                mov     dword ptr [rbp+200h+var_B0], esi
                mov     dword ptr [rbp+200h+var_B0+4], edi
                mov     [rbp+200h+var_A0], rdi
                mov     dword ptr [rbp+200h+var_98], edi
                lea     rax, [rbp+200h+var_E0]
                mov     [rsp+300h+var_2D0], rax
                lea     rax, [rsp+300h+var_2B0]
                mov     [rsp+300h+var_2D8], rax
                movzx   eax, [rsp+300h+var_2AE]
                mov     byte ptr [rsp+300h+var_2E0], al
                mov     r9, rbx
                mov     r8, [rsp+300h+var_298]
                lea     rdx, [rbp+200h+var_1A0]
                mov     rcx, r15
;   } // starts at 7FF6BD25FEA3
;   try {
                call    sub_7FF6BD263E80
                test    al, al
                jz      loc_7FF6BD2602BD
                cmp     [rsp+300h+var_2B0], dil
                jz      loc_7FF6BD26006D
                lea     r8, [r15+8Ch]
                mov     eax, [r15+88h]
                cmp     eax, [r8]
                jnz     short loc_7FF6BD25FF7D
                mov     ecx, 878h
                lea     rdx, [r15+80h]
                call    sub_7FF6BA64EC90

loc_7FF6BD25FF7D:                       ; CODE XREF: sub_7FF6BD25F820+74A↑j
                lea     ecx, [rax+1]
                mov     [r15+88h], ecx
                cdqe
                imul    rcx, rax, 78h ; 'x'
                mov     rdi, [r15+80h]
                add     rdi, rcx
                mov     [rbp+200h+var_250], rdi
                mov     eax, [rbx+8]
                mov     [rdi], eax
                mov     rax, [rsp+300h+var_298]
                mov     eax, [rax]
                mov     [rdi+4], eax
                lea     rbx, [rdi+8]
                mov     [rbp+200h+var_278], rbx
                xor     ecx, ecx
                mov     [rbx], rcx
;   } // starts at 7FF6BD25FF41
;   try {
                movsxd  rsi, [rbp+200h+var_108]
                mov     r14, [rbp+200h+Src]
                mov     [rbx+8], esi
                lea     rax, [rbx+0Ch]
                test    esi, esi
                jnz     short loc_7FF6BD25FFD4
                mov     [rax], ecx
                jmp     short loc_7FF6BD260009
; ---------------------------------------------------------------------------

loc_7FF6BD25FFD4:                       ; CODE XREF: sub_7FF6BD25F820+7AE↑j
                mov     [rsp+300h+var_2D0], rax
                mov     eax, [rbp+200h+var_108]
                mov     dword ptr [rsp+300h+var_2D8], eax
                mov     [rsp+300h+var_2E0], rbx
                xor     r9d, r9d
                mov     r8d, esi
                mov     edx, 1
                mov     ecx, edx
                call    sub_7FF6BA64E740
                mov     r8, rsi         ; Size
                mov     rdx, r14        ; Src
                mov     rcx, [rbx]      ; void *
                call    memcpy
                nop
;   } // starts at 7FF6BD25FFB7

loc_7FF6BD260009:                       ; CODE XREF: sub_7FF6BD25F820+7B2↑j
;   try {
                mov     rax, [rbp+200h+var_100]
                mov     [rdi+18h], rax
                mov     eax, [rsp+300h+var_2AC]
                mov     [rdi+20h], eax
                lea     rcx, [rdi+28h]
                mov     [rbp+200h+var_278], rcx
                xor     edi, edi
                mov     [rcx], rdi
                mov     [rcx+8], rdi
                mov     [rcx+20h], rdi
                mov     [rcx+28h], edi
                mov     dword ptr [rcx+2Ch], 80h
                mov     esi, 0FFFFFFFFh
                mov     [rcx+30h], esi
                mov     [rcx+34h], edi
                mov     [rcx+40h], rdi
                mov     [rcx+48h], edi
                lea     rdx, [rbp+200h+var_E0]
;   } // starts at 7FF6BD260009
;   try {
                call    sub_7FF6BB063AF0
                nop
                mov     r14, [rbp+200h+var_238]
                mov     byte ptr [r14], 1
                mov     [rsp+300h+var_2AF], 1
                or      dword ptr [r15+14h], 4
                jmp     short loc_7FF6BD26007C
; ---------------------------------------------------------------------------

loc_7FF6BD26006D:                       ; CODE XREF: sub_7FF6BD25F820+733↑j
                mov     eax, [r13+8]
                shr     eax, 1Eh
                test    al, 1
                jnz     loc_7FF6BD2602B8

loc_7FF6BD26007C:                       ; CODE XREF: sub_7FF6BD25F820+84B↑j
                mov     dword ptr [rbp+200h+var_98], edi
                mov     rcx, [rbp+200h+var_A0]
                test    rcx, rcx
                jz      short loc_7FF6BD260094
;   } // starts at 7FF6BD260053
;   try {
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD260094:                       ; CODE XREF: sub_7FF6BD25F820+86C↑j
                mov     dword ptr [rbp+200h+var_D8], edi
                cmp     dword ptr [rbp+200h+var_D8+4], 0
                jz      short loc_7FF6BD2600CC
                lea     rax, [rbp+200h+var_D8+4]
                mov     [rsp+300h+var_2D8], rax
                mov     dword ptr [rsp+300h+var_2E0], edi
                lea     r9, [rbp+200h+var_E0]
                xor     r8d, r8d
                mov     edx, 8
                mov     ecx, 18h
                call    sub_7FF6BA64BD90

loc_7FF6BD2600CC:                       ; CODE XREF: sub_7FF6BD25F820+881↑j
                mov     dword ptr [rbp+200h+var_B0], esi
                mov     dword ptr [rbp+200h+var_B0+4], edi
                mov     dword ptr [rbp+200h+var_B8], edi
                cmp     dword ptr [rbp+200h+var_B8+4], 80h
                jbe     short loc_7FF6BD260103
                mov     dword ptr [rbp+200h+var_B8+4], 80h
                xor     edx, edx
                lea     rcx, [rbp+200h+var_D0]
                call    sub_7FF6BA64C1F0
                nop
;   } // starts at 7FF6BD26008E

loc_7FF6BD260103:                       ; CODE XREF: sub_7FF6BD25F820+8C8↑j
;   try {
                mov     rcx, [rbp+200h+var_C0]
                test    rcx, rcx
                jz      short loc_7FF6BD260115
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD260115:                       ; CODE XREF: sub_7FF6BD25F820+8ED↑j
                mov     rcx, [rbp+200h+var_E0]
                test    rcx, rcx
                jz      short loc_7FF6BD260127
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD260103

loc_7FF6BD260127:                       ; CODE XREF: sub_7FF6BD25F820+3A0↑j
                                        ; sub_7FF6BD25F820:loc_7FF6BD25FC09↑j ...
;   try {
                lea     rax, [rbp+200h+var_1A0]
                mov     [rsp+300h+var_2D0], rax
                lea     rax, [rsp+300h+var_290]
                mov     [rsp+300h+var_2D8], rax
                mov     rbx, [rbp+200h+var_260]
                mov     [rsp+300h+var_2E0], rbx
                mov     r9, [rbp+200h+var_230]
                mov     r8, [rbp+200h+var_258]
                mov     rdx, r13
                mov     rcx, [r15+60h]
                call    sub_7FF6BD25DC60
                test    al, al
                jnz     loc_7FF6BD25FBA5

loc_7FF6BD26015F:                       ; CODE XREF: sub_7FF6BD25F820+378↑j
                cmp     [rsp+300h+var_2AF], 0
                jz      short loc_7FF6BD26016E
                mov     rcx, r15
                call    sub_7FF6BD2735B0

loc_7FF6BD26016E:                       ; CODE XREF: sub_7FF6BD25F820+944↑j
                mov     dil, 1
;   } // starts at 7FF6BD260127

loc_7FF6BD260171:                       ; CODE XREF: sub_7FF6BD25F820:loc_7FF6BD26036D↓j
                                        ; sub_7FF6BD25F820+BA6↓j ...
;   try {
                mov     rbx, [rbp+200h+var_1E0]
                test    rbx, rbx
                jz      short loc_7FF6BD2601A9
                mov     eax, esi
                lock xadd [rbx+8], eax
                cmp     eax, 1
                jnz     short loc_7FF6BD2601A9
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                mov     eax, esi
                lock xadd [rbx+0Ch], eax
                cmp     eax, 1
                jnz     short loc_7FF6BD2601A9
                mov     rax, [rbx]
                mov     edx, 1
                mov     rcx, rbx
                call    qword ptr [rax+8]
                nop

loc_7FF6BD2601A9:                       ; CODE XREF: sub_7FF6BD25F820+958↑j
                                        ; sub_7FF6BD25F820+964↑j ...
                mov     rbx, qword ptr [rbp+200h+var_200+8]
                test    rbx, rbx
                jz      short loc_7FF6BD2601DD
                mov     eax, esi
                lock xadd [rbx+8], eax
                cmp     eax, 1
                jnz     short loc_7FF6BD2601DD
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                lock xadd [rbx+0Ch], esi
                cmp     esi, 1
                jnz     short loc_7FF6BD2601DD
                mov     r8, [rbx]
                mov     edx, esi
                mov     rcx, rbx
                call    qword ptr [r8+8]
                nop
;   } // starts at 7FF6BD260171

loc_7FF6BD2601DD:                       ; CODE XREF: sub_7FF6BD25F820+990↑j
                                        ; sub_7FF6BD25F820+99C↑j ...
;   try {
                lea     rax, off_7FF6C317F898
                mov     [rbp+200h+var_220], rax
                lea     rcx, [rbp+200h+var_1A0]
                call    sub_7FF6BA950F20
                movzx   eax, dil

loc_7FF6BD2601F5:                       ; CODE XREF: sub_7FF6BD25F820+8D↑j
                                        ; sub_7FF6BD25F820+152↑j ...
                mov     rcx, [rbp+200h+var_40]
                xor     rcx, rsp        ; StackCookie
;   } // starts at 7FF6BD2601DD
                call    __security_check_cookie
                mov     rbx, [rsp+300h+arg_18]
                add     rsp, 2D0h
                pop     r15
                pop     r14
                pop     r13
                pop     r12
                pop     rdi
                pop     rsi
                pop     rbp
                retn
; ---------------------------------------------------------------------------

loc_7FF6BD26021F:                       ; CODE XREF: sub_7FF6BD25F820+4B9↑j
                cmp     cs:byte_7FF6C6B68418, 2
                jb      loc_7FF6BD260418
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rsp+300h+var_288]
                mov     rcx, r13
;   try {
                call    sub_7FF6BAA98740
                nop
                cmp     dword ptr [rax+8], 0
                jz      short loc_7FF6BD26024B
                mov     rbx, [rax]
                jmp     short loc_7FF6BD26024E
; ---------------------------------------------------------------------------

loc_7FF6BD26024B:                       ; CODE XREF: sub_7FF6BD25F820+A24↑j
                mov     rbx, r12

loc_7FF6BD26024E:                       ; CODE XREF: sub_7FF6BD25F820+A29↑j
                lea     rdx, aFfieldGetname ; "FField::GetName"
                mov     rcx, rdi
;   } // starts at 7FF6BD26023A
;   try {
                call    sub_7FF6BA7B4B10
                test    al, al
                jz      short loc_7FF6BD260270
                lea     rcx, [rdi+20h]
                lea     rdx, [rbp+200h+var_278]
                call    sub_7FF6BA83CFA0
                jmp     short loc_7FF6BD260281
; ---------------------------------------------------------------------------

loc_7FF6BD260270:                       ; CODE XREF: sub_7FF6BD25F820+A3F↑j
                lea     rdx, aNone      ; "None"
                lea     rcx, [rbp+200h+var_278]
                call    sub_7FF6BA66EDD0
                nop
;   } // starts at 7FF6BD260258

loc_7FF6BD260281:                       ; CODE XREF: sub_7FF6BD25F820+A4E↑j
;   try {
                cmp     [rbp+200h+var_270], 0
                cmovnz  r12, [rbp+200h+var_278]
                mov     r9, rbx
                mov     r8, r12
                lea     rdx, off_7FF6C3BDA6D0 ; "Server received unwanted property value"...
                lea     rcx, byte_7FF6C6B68418
                call    sub_7FF6BA751C70
                nop
;   } // starts at 7FF6BD260281
;   try {
                mov     rcx, [rbp+200h+var_278]
                test    rcx, rcx
                jz      short loc_7FF6BD2602B3
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD2602A4

loc_7FF6BD2602B3:                       ; CODE XREF: sub_7FF6BD25F820+A8B↑j
;   try {
                jmp     loc_7FF6BD260408
; ---------------------------------------------------------------------------

loc_7FF6BD2602B8:                       ; CODE XREF: sub_7FF6BD25F820+856↑j
                mov     dil, 1
                jmp     short loc_7FF6BD2602C0
; ---------------------------------------------------------------------------

loc_7FF6BD2602BD:                       ; CODE XREF: sub_7FF6BD25F820+728↑j
                xor     dil, dil

loc_7FF6BD2602C0:                       ; CODE XREF: sub_7FF6BD25F820+A9B↑j
                xor     ebx, ebx
                mov     dword ptr [rbp+200h+var_98], ebx
                mov     rcx, [rbp+200h+var_A0]
                test    rcx, rcx
                jz      short loc_7FF6BD2602DA
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD2602DA:                       ; CODE XREF: sub_7FF6BD25F820+AB2↑j
                mov     dword ptr [rbp+200h+var_D8], ebx
                cmp     dword ptr [rbp+200h+var_D8+4], 0
                jz      short loc_7FF6BD260312
                lea     rax, [rbp+200h+var_D8+4]
                mov     [rsp+300h+var_2D8], rax
                mov     dword ptr [rsp+300h+var_2E0], ebx
                lea     r9, [rbp+200h+var_E0]
                xor     r8d, r8d
                mov     edx, 8
                mov     ecx, 18h
                call    sub_7FF6BA64BD90

loc_7FF6BD260312:                       ; CODE XREF: sub_7FF6BD25F820+AC7↑j
                mov     dword ptr [rbp+200h+var_B0], esi
                mov     dword ptr [rbp+200h+var_B0+4], ebx
                mov     dword ptr [rbp+200h+var_B8], ebx
                cmp     dword ptr [rbp+200h+var_B8+4], 80h
                jbe     short loc_7FF6BD260349
                mov     dword ptr [rbp+200h+var_B8+4], 80h
                xor     edx, edx
                lea     rcx, [rbp+200h+var_D0]
                call    sub_7FF6BA64C1F0
                nop
;   } // starts at 7FF6BD2602B3

loc_7FF6BD260349:                       ; CODE XREF: sub_7FF6BD25F820+B0E↑j
;   try {
                mov     rcx, [rbp+200h+var_C0]
                test    rcx, rcx
                jz      short loc_7FF6BD26035B
                call    sub_7FF6BA6E0B20
                nop

loc_7FF6BD26035B:                       ; CODE XREF: sub_7FF6BD25F820+B33↑j
                mov     rcx, [rbp+200h+var_E0]
                test    rcx, rcx
                jz      short loc_7FF6BD26036D
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD260349

loc_7FF6BD26036D:                       ; CODE XREF: sub_7FF6BD25F820+B45↑j
;   try {
                jmp     loc_7FF6BD260171
; ---------------------------------------------------------------------------

loc_7FF6BD260372:                       ; CODE XREF: sub_7FF6BD25F820+670↑j
                                        ; sub_7FF6BD25F820+67D↑j ...
                cmp     cs:byte_7FF6C6B68438, 2
                jb      short loc_7FF6BD2603C3
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rsp+300h+var_288]
                mov     rcx, r13
                call    sub_7FF6BAA98740
                nop
;   } // starts at 7FF6BD26036D
;   try {
                cmp     dword ptr [rax+8], 0
                jz      short loc_7FF6BD260398
                mov     r12, [rax]

loc_7FF6BD260398:                       ; CODE XREF: sub_7FF6BD25F820+B73↑j
                mov     r9, r12
                mov     r8d, [rbx+8]
                lea     rdx, off_7FF6C3BDA790 ; "ReceivedBunch: Invalid replicated field"...
                lea     rcx, byte_7FF6C6B68438
                call    sub_7FF6BA751C70
                nop
;   } // starts at 7FF6BD26038F
;   try {
                mov     rcx, [rsp+300h+var_288]
                test    rcx, rcx
                jz      short loc_7FF6BD2603C3
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD2603B3

loc_7FF6BD2603C3:                       ; CODE XREF: sub_7FF6BD25F820+B59↑j
                                        ; sub_7FF6BD25F820+B9B↑j
;   try {
                xor     dil, dil
                jmp     loc_7FF6BD260171
; ---------------------------------------------------------------------------

loc_7FF6BD2603CB:                       ; CODE XREF: sub_7FF6BD25F820+389↑j
                cmp     cs:byte_7FF6C6B68418, 2
                jb      short loc_7FF6BD260418
                xor     r9d, r9d
                xor     r8d, r8d
                lea     rdx, [rsp+300h+var_288]
                mov     rcx, r13
                call    sub_7FF6BAA98740
                nop
;   } // starts at 7FF6BD2603C3
;   try {
                cmp     dword ptr [rax+8], 0
                jz      short loc_7FF6BD2603F1
                mov     r12, [rax]

loc_7FF6BD2603F1:                       ; CODE XREF: sub_7FF6BD25F820+BCC↑j
                mov     r8, r12
                lea     rdx, off_7FF6C3BDA530 ; "ReceivedBunch: Error reading field: %s"
                lea     rcx, byte_7FF6C6B68418
                call    sub_7FF6BA751C70
                nop
;   } // starts at 7FF6BD2603E8

loc_7FF6BD260408:                       ; CODE XREF: sub_7FF6BD25F820:loc_7FF6BD2602B3↑j
;   try {
                mov     rcx, [rsp+300h+var_288]
                test    rcx, rcx
                jz      short loc_7FF6BD260418
                call    sub_7FF6BA6E0B20
                nop
;   } // starts at 7FF6BD260408

loc_7FF6BD260418:                       ; CODE XREF: sub_7FF6BD25F820+A06↑j
                                        ; sub_7FF6BD25F820+BB2↑j ...
                xor     dil, dil
                jmp     loc_7FF6BD260171
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 7FF6BD25F820
sub_7FF6BD25F820 endp
