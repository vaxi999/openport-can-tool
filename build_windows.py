"""Build a standard importable PE32 with GCC/binutils, without a bundled CRT.

Only LoadLibraryW and GetProcAddress are bootstrap imports; the PE loader
resolves them normally. All remaining Windows/J2534 exports bind at runtime.
"""
from pathlib import Path
import hashlib,json,re,struct,subprocess
ROOT=Path(__file__).resolve().parent
BUILD=ROOT/'build';BUILD.mkdir(exist_ok=True)
obj=BUILD/'probe.elf.o';coff=BUILD/'probe.coff.o';exe=ROOT/'OPENPORT_TEST_TABLE.exe'
subprocess.run(['gcc','-m32','-mpreferred-stack-boundary=2','-mincoming-stack-boundary=2','-std=c99','-Os','-Wall','-Wextra','-Wno-misleading-indentation','-ffreestanding','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-strict-aliasing','-fno-pie','-fno-pic','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-c',str(ROOT/'source/openport_test_table.c'),'-o',str(obj)],check=True)
def elf32_to_coff(source,destination):
    # GNU objcopy preserves ELF relocation numbers when crossing these two
    # formats. Translate symbols/relocations explicitly rather than accepting
    # a superficially valid but incorrectly linked Windows executable.
    b=source.read_bytes();assert b[:7]==b'\x7fELF\x01\x01\x01'
    shoff=struct.unpack_from('<I',b,32)[0];entsize,nsections,shstr=struct.unpack_from('<HHH',b,46)
    headers=[struct.unpack_from('<10I',b,shoff+i*entsize) for i in range(nsections)]
    h=headers[shstr];strings=b[h[4]:h[4]+h[5]]
    def name(table,offset):return table[offset:table.index(0,offset)].decode()
    names=[name(strings,h[0]) for h in headers]
    selected=[i for i,h in enumerate(headers) if h[2]&2]
    section_map={index:i+1 for i,index in enumerate(selected)}
    string_data=bytearray(b'\0\0\0\0');string_offsets={}
    def long_name(s):
        if s not in string_offsets:
            string_offsets[s]=len(string_data);string_data.extend(s.encode()+b'\0')
        return string_offsets[s]
    def symbol_name(s):
        if len(s.encode())<=8:return s.encode().ljust(8,b'\0')
        return struct.pack('<II',0,long_name(s))
    sym_index=next(i for i,h in enumerate(headers) if h[1]==2);sh=headers[sym_index]
    st=headers[sh[6]];sym_strings=b[st[4]:st[4]+st[5]];symbols=[];symbol_map={}
    for index in range(sh[5]//16):
        no,value,size,info,other,section=struct.unpack_from('<IIIBBH',b,sh[4]+index*16)
        if index==0 or info&15==4:continue
        if section and section not in section_map and section!=0xfff1:continue
        s=name(sym_strings,no) if no else (names[section] if section<len(names) else '')
        if not s:continue
        symbol_map[index]=len(symbols)
        symbols.append((s,value,section_map.get(section,-1 if section==0xfff1 else 0),0x20 if info&15==2 else 0,2 if info>>4 else 3))
    section_data={i:bytearray() if headers[i][1]==8 else bytearray(b[headers[i][4]:headers[i][4]+headers[i][5]]) for i in selected}
    relocs={i:[] for i in selected};expected_relocations=[]
    for h in headers:
        if h[1]!=9 or h[7] not in section_map:continue
        assert h[6]==sym_index
        for at in range(h[4],h[4]+h[5],8):
            offset,info=struct.unpack_from('<II',b,at);symbol,kind=info>>8,info&255
            assert kind in(1,2) and symbol in symbol_map,(kind,symbol)
            addend=struct.unpack_from('<I',section_data[h[7]],offset)[0]
            expected_relocations.append((names[h[7]],offset,symbols[symbol_map[symbol]][0],addend,kind))
            if kind==2:
                struct.pack_into('<I',section_data[h[7]],offset,(addend+4)&0xffffffff)
            relocs[h[7]].append(struct.pack('<IIH',offset,symbol_map[symbol],6 if kind==1 else 20))
    out=bytearray(20+40*len(selected));section_rows=[]
    for index in selected:
        h=headers[index];s=names[index];sn=s.encode().ljust(8,b'\0') if len(s.encode())<=8 else ('/'+str(long_name(s))).encode().ljust(8,b'\0')
        assert len(sn)==8
        while len(out)%4:out.append(0)
        data_at=len(out) if section_data[index] else 0;out.extend(section_data[index])
        reloc_at=len(out) if relocs[index] else 0
        for r in relocs[index]:out.extend(r)
        alignment=max(1,h[8]);assert alignment&(alignment-1)==0
        flags=(alignment.bit_length()<<20)|0x40000000
        flags|=0x80 if h[1]==8 else (0x20|0x20000000 if h[2]&4 else 0x40)
        if h[2]&1:flags|=0x80000000
        section_rows.append(struct.pack('<8sIIIIIIHHI',sn,0,0,h[5],data_at,reloc_at,0,len(relocs[index]),0,flags))
    sym_at=len(out)
    for s,value,section,typ,storage in symbols:out.extend(struct.pack('<8sIhHBB',symbol_name(s),value,section,typ,storage,0))
    struct.pack_into('<I',string_data,0,len(string_data));out.extend(string_data)
    struct.pack_into('<HHIIIHH',out,0,0x14c,len(selected),0,sym_at,len(symbols),0,0x100)
    for i,row in enumerate(section_rows):out[20+40*i:60+40*i]=row
    destination.write_bytes(out)
    return expected_relocations
expected_relocations=elf32_to_coff(obj,coff)
subprocess.run(['ld','-m','i386pe','--entry','entry','--subsystem','windows','--image-base','0x400000','--stack','0x100000,0x1000','--dynamicbase','--nxcompat','--enable-reloc-section','--no-insert-timestamp','-o',str(exe),str(coff)],check=True)
symbols={m.group(3):int(m.group(1),16) for line in subprocess.check_output(['nm',str(exe)],text=True).splitlines() if (m:=re.match(r'^([0-9a-fA-F]+)\s+(\w)\s+(\S+)$',line))}
raw=bytearray(exe.read_bytes());pe=struct.unpack_from('<I',raw,0x3c)[0];assert raw[pe:pe+4]==b'PE\0\0'
machine,sections=struct.unpack_from('<HH',raw,pe+4);opt=pe+24;assert machine==0x14c and struct.unpack_from('<H',raw,opt)[0]==0x10b
image_base=struct.unpack_from('<I',raw,opt+28)[0];section_at=opt+struct.unpack_from('<H',raw,pe+20)[0]
layout=[]
for i in range(sections):
    p=section_at+40*i;name=bytes(raw[p:p+8]).rstrip(b'\0').decode();vsize,rva,size,offset=struct.unpack_from('<IIII',raw,p+8)
    layout.append(dict(name=name,rva=rva,size=size,offset=offset,virtual_size=vsize))
def file_offset(rva):
    for s in layout:
        if s['rva']<=rva<s['rva']+s['size']:return s['offset']+rva-s['rva']
    raise AssertionError(f'Unmapped file-backed RVA {rva:x}')
for section,offset,target,addend,kind in expected_relocations:
    address=symbols[section]+offset
    expected=(symbols[target]+addend-(address if kind==2 else 0))&0xffffffff
    actual=struct.unpack_from('<I',raw,file_offset(address-image_base))[0]
    assert actual==expected,(section,hex(offset),target,hex(expected),hex(actual))
blob=symbols['import_blob']-image_base;iat=symbols['bootstrap_iat']-image_base
at=file_offset(blob);iat_at=file_offset(iat)
struct.pack_into('<IIIII',raw,at,blob+40,0,0,blob+64,iat)
struct.pack_into('<III',raw,at+40,blob+80,blob+104,0)
raw[at+64:at+77]=b'kernel32.dll\0'
raw[at+80:at+95]=b'\0\0LoadLibraryW\0'
raw[at+104:at+121]=b'\0\0GetProcAddress\0'
struct.pack_into('<III',raw,iat_at,blob+80,blob+104,0)
struct.pack_into('<II',raw,opt+96+8,blob,40)
struct.pack_into('<II',raw,opt+96+12*8,iat,12)
# Validate every imported name and every base relocation; import RVAs must
# never acquire base relocation entries after the bootstrap patch.
reloc_rva,reloc_len=struct.unpack_from('<II',raw,opt+96+5*8);assert reloc_len>0
rp=file_offset(reloc_rva);end=rp+reloc_len;relocations=[]
while rp<end:
    page,n=struct.unpack_from('<II',raw,rp);assert n>=8 and n%2==0
    for k in range(rp+8,rp+n,2):
        item=struct.unpack_from('<H',raw,k)[0]
        if item>>12==0:continue
        assert item>>12==3
        address=page+(item&0xfff);assert not(blob<=address<blob+256 or iat<=address<iat+12)
        relocations.append(address)
    rp+=n
assert rp==end and len(relocations)>10
assert struct.unpack_from('<I',raw,file_offset(symbols['entry']-image_base))[0]!=0
if len(raw)%2:raw.append(0)
struct.pack_into('<I',raw,opt+64,0);checksum=0
for k in range(0,len(raw),2):checksum=(checksum+int.from_bytes(raw[k:k+2],'little'));checksum=(checksum&0xffff)+(checksum>>16)
checksum=(checksum&0xffff)+(checksum>>16);checksum=(checksum&0xffff)+len(raw);struct.pack_into('<I',raw,opt+64,checksum)
exe.write_bytes(raw)
report=dict(result='PASS_PE32_STRUCTURE_IMPORTS_AND_ASLR_RELOCATIONS',file=exe.name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),machine='x86 / PE32',imports=['kernel32!LoadLibraryW','kernel32!GetProcAddress'],base_relocations=len(relocations),all_ELF_to_PE_relocation_values_verified=len(expected_relocations),CRT_or_Python_required=False,actual_Windows_or_OpenPort_execution_tested=False)
(ROOT/'verification_build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
