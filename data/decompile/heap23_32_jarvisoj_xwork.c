void __fastcall __noreturn sub_4010F0(
    __int64 (__fastcall *a1)(_QWORD, __int64, __int64),
    int a2,
    __int64 a3,
    void (__fastcall *a4)(_QWORD, __int64, __int64),
    __int64 a5,
    __int64 a6,
    __int64 a7)
{
int v10; // r11d
__int64 (__fastcall *v11)(_QWORD, __int64, __int64); // r10
int v16; // r13d
int v17; // edi
int v18; // esi
int v34; // eax
int v35; // eax
__int64 v36; // [rsp+0h] [rbp-48h]
__int64 v37; // [rsp+0h] [rbp-48h]
__int64 v38; // [rsp+8h] [rbp-40h]
__int64 v39; // [rsp+8h] [rbp-40h]
int v40; // [rsp+10h] [rbp-38h] BYREF
unsigned int v41; // [rsp+14h] [rbp-34h] BYREF
unsigned int v42; // [rsp+18h] [rbp-30h] BYREF
unsigned int v43[11]; // [rsp+1Ch] [rbp-2Ch] BYREF

_RAX = 0;
v10 = a2;
v11 = a1;
__asm { cpuid }
dword_6CC684 = _RAX;
v40 = 0;
v41 = 0;
v42 = 0;
if ( (_DWORD)_RCX != 1818588270 || (_DWORD)_RBX != 1970169159 || (_DWORD)_RDX != 1231384169 )
{
if ( (_DWORD)_RCX == 1145913699 && (_DWORD)_RBX == 1752462657 && (_DWORD)_RDX == 1769238117 )
{
  v39 = a6;
  v37 = a5;
  sub_401080((unsigned int *)&v40, (int *)&v41, v43, &v42);
  _RAX = 0x80000000LL;
  a5 = v37;
  a6 = v39;
  __asm { cpuid }
  if ( (unsigned int)_RAX > 0x80000000 )
  {
    _RAX = 2147483649LL;
    __asm { cpuid }
    dword_6CC6A8 = _RAX;
    dword_6CC6AC = _RBX;
    unk_6CC6B0 = _RCX;
    dword_6CC6B4 = _RDX;
  }
  v17 = v41;
  if ( v40 == 21 && v41 - 96 <= 0x1F )
    dword_6CC6C0 |= 0x10u;
  v18 = 2;
  v16 = dword_6CC690;
}
else
{
  v16 = dword_6CC690;
  v17 = v41;
  v18 = 3;
}
LABEL_6:
LOBYTE(_RAX) = dword_6CC694;
if ( (dword_6CC694 & 0x100) != 0 )
  dword_6CC6C0 |= 0x4000u;
if ( (dword_6CC694 & 0x8000) != 0 )
  dword_6CC6C0 |= 0x8000u;
if ( dword_6CC684 > 6 )
{
  _RAX = 7;
  __asm { cpuid }
  dword_6CC698 = _RAX;
  dword_6CC69C = _RBX;
  dword_6CC6A0 = _RCX;
  dword_6CC6A4 = _RDX;
}
if ( (v16 & 0x8000000) != 0 )
{
  __asm { xgetbv }
  if ( (_RAX & 6) == 6 )
  {
    if ( (v16 & 0x10000000) != 0 )
      dword_6CC6C0 |= 0x40u;
    if ( (dword_6CC69C & 0x20) != 0 )
      dword_6CC6C0 |= 0xC00u;
    if ( (_RAX & 0xE0) == 0xE0 && (dword_6CC69C & 0x10000) != 0 )
    {
      v34 = dword_6CC6C0;
      if ( (dword_6CC69C & 0x20000) != 0 )
        BYTE1(v34) = BYTE1(dword_6CC6C0) | 0x30;
      else
        BYTE1(v34) = BYTE1(dword_6CC6C0) | 0x10;
      dword_6CC6C0 = v34;
    }
    if ( (v16 & 0x1000) != 0 )
      dword_6CC6C0 |= 0x80u;
    if ( (byte_6CC6B2 & 1) != 0 )
      dword_6CC6C0 |= 0x100u;
  }
}
if ( v18 != 1 || v40 != 6 )
  goto LABEL_15;
if ( v17 != 63 )
{
  if ( v17 == 60 )
  {
    if ( v42 <= 3 )
      goto LABEL_39;
    goto LABEL_15;
  }
  if ( (unsigned int)(v17 - 69) <= 1 )
    goto LABEL_38;
  if ( v17 == 61 )
  {
    if ( v42 > 4 )
      goto LABEL_15;
LABEL_39:
    dword_6CC69C &= 0xFFFFF7EF;
    goto LABEL_15;
  }
  if ( v17 == 71 )
  {
LABEL_38:
    if ( v42 > 1 )
      goto LABEL_15;
    goto LABEL_39;
  }
  if ( v17 != 86 )
    goto LABEL_15;
}
if ( v42 <= 2 )
  goto LABEL_39;
LABEL_15:
dword_6CC6BC = v17;
dword_6CC680 = v18;
dword_6CC6B8 = v40;
sub_400DE0(v11, v10, a3, a4, a5, a6, a7);
}
v38 = a6;
v36 = a5;
sub_401080((unsigned int *)&v40, (int *)&v41, v43, &v42);
v16 = dword_6CC690;
a5 = v36;
a6 = v38;
if ( v40 != 6 )
{
LABEL_33:
v18 = 1;
v17 = v41;
goto LABEL_6;
}
v41 += v43[0];
if ( v41 <= 0x2F )
{
if ( v41 >= 0x2E )
  goto LABEL_71;
if ( v41 > 0x1F )
{
  if ( v41 == 38 )
    goto LABEL_50;
  if ( v41 == 44 || v41 == 37 )
  {
LABEL_71:
    dword_6CC6C0 |= 0x33u;
    goto LABEL_33;
  }
}
else
{
  if ( v41 >= 0x1E || v41 == 26 )
    goto LABEL_71;
  if ( v41 == 28 )
  {
LABEL_50:
    dword_6CC6C0 |= 4u;
    goto LABEL_33;
  }
}
LABEL_70:
if ( (dword_6CC690 & 0x10000000) == 0 )
  goto LABEL_33;
goto LABEL_71;
}
if ( v41 != 77 )
{
if ( v41 <= 0x4D )
{
  if ( v41 != 55 && v41 != 74 )
    goto LABEL_70;
}
else if ( v41 != 90 && v41 != 93 )
{
  if ( v41 != 87 )
    goto LABEL_70;
  v35 = dword_6CC6C0 | 0x20000;
LABEL_66:
  dword_6CC6C0 = v35 | 0x230;
  goto LABEL_33;
}
}
v35 = dword_6CC6C0;
goto LABEL_66;
}