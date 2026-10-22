#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define GW_HOST_TEST
#include "../source/openport_test_table.c"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static WChar field[64][22000];
static unsigned now,writes,opens,closes,disconnects,frees,filter_calls,write_mode,read_mode,connect_mode,ioctl_mode,filter_mode;
static PassMessage sent[512];static char csv_capture[131072],trace_capture[131072];static unsigned csv_n,trace_n;
static unsigned wcopy(WChar *p,const char *s){unsigned n=0;while(s[n]){p[n]=(uint8_t)s[n];n++;}p[n]=0;return n;}
static unsigned wh(Handle h){CHECK((uintptr_t)h<64);return (unsigned)(uintptr_t)h;}
static void set(Handle h,const char *s){wcopy(field[wh(h)],s);}
static int settext(Handle h,const WChar *s){unsigned i=0;if(!h)return 0;while(s[i] && i<21999){field[wh(h)][i]=s[i];i++;}field[wh(h)][i]=0;return 1;}
static int gettext(Handle h,WChar *s,int max){int i=0;while(field[wh(h)][i] && i<max-1){s[i]=field[wh(h)][i];i++;}s[i]=0;return i;}
static LResult sendmsg(Handle h,unsigned m,uintptr_t w,intptr_t l){(void)w;(void)l;return m==0xf0?field[wh(h)][0]=='1':0;}
static int enable(Handle h,int v){(void)h;(void)v;return 1;}
static Dword ticks(void){return now;}
static void sleepfn(Dword v){now+=v;}
static int writefile(Handle h,const void *p,Dword n,Dword *w,void *o){(void)o;*w=n;if(h==(Handle)1001){CHECK(trace_n+n<sizeof(trace_capture));memcpy(trace_capture+trace_n,p,n);trace_n+=n;trace_capture[trace_n]=0;}if(h==(Handle)1002){CHECK(csv_n+n<sizeof(csv_capture));memcpy(csv_capture+csv_n,p,n);csv_n+=n;csv_capture[csv_n]=0;}return 1;}
static int freefn(Handle h){CHECK(h==(Handle)100);frees++;return 1;}
static Dword lasterrorfn(void){return 193;}
static Handle loadex(const WChar *p,Handle h,Dword flags){CHECK(p[0]=='C' && !h && flags==8);return (Handle)100;}
static Status op(void *p,Dword *d){CHECK(!p);*d=10;opens++;return 0;}
static Status closefn(Dword d){CHECK(d==10);closes++;return 0;}
static Status connectfn(Dword d,Dword proto,Dword flags,Dword rate,Dword *c){CHECK(d==10 && proto==5 && flags==(extended?0x100u:0) && rate==bitrate);*c=20;return connect_mode?7:0;}
static Status disconnectfn(Dword c){CHECK(c==20);disconnects++;return 0;}
static Status writefn(Dword ch,PassMessage *m,Dword *n,Dword timeout){
    CHECK(ch==20 && *n==1 && timeout==100 && m->ProtocolID==5 && m->DataSize>=4 && m->DataSize<=12);
    CHECK(m->ExtraDataIndex==m->DataSize && m->TxFlags==(extended?0x100u:0));CHECK(writes<512);sent[writes++]=*m;
    if(write_mode==1)return 7;if(write_mode==2){*n=0;return 0;}return 0;
}
static Status filterfn(Dword c,Dword type,PassMessage *mask,PassMessage *pat,PassMessage *flow,Dword *id){unsigned i;CHECK(c==20 && type==1 && !flow && mask->DataSize==4 && pat->DataSize==4);CHECK(mask->TxFlags==(extended?0x100u:0));for(i=0;i<4;i++)CHECK(!mask->Data[i] && !pat->Data[i]);*id=30;filter_calls++;return filter_mode?7:0;}
static Status ioctlfn(Dword c,Dword op,void *in,void *out){CHECK(c==20 && !out);if(op==2){ConfigList *a=in;CHECK(a->NumOfParams==1 && a->ConfigPtr->Parameter==3 && !a->ConfigPtr->Value);}else CHECK(op==8 && !in);return ioctl_mode?7:0;}
static Status errorfn(char *out){strcpy(out,"mock driver error");return 0;}
static Status versionfn(Dword d,char *a,char *b,char *c){CHECK(d==10);strcpy(a,"mock-fw");strcpy(b,"mock-dll");strcpy(c,"04.04");return 0;}
static Status readfn(Dword ch,PassMessage *m,Dword *n,Dword timeout){
    CHECK(ch==20 && *n==64 && !timeout);*n=0;
    if(read_mode==1)return 7;if(read_mode==2){*n=65;return 0;}if(read_mode==3)return 0x12;if(!read_mode)return 16;
    gw_zero(m,5*sizeof(*m));m[0].ProtocolID=5;m[0].DataSize=6;m[0].Data[2]=6;m[0].Data[3]=0xdf;m[0].Data[4]=0xab;m[0].Data[5]=0xcd;m[0].Timestamp=1234;
    m[1]=m[0];m[1].RxStatus=1; /* TX echo is not a received response. */
    m[2]=m[0];m[2].RxStatus=8; /* START indication is not a payload. */
    m[3]=m[0];m[3].RxStatus=0x100;m[3].Data[0]=0x18;m[3].Data[1]=0xda;m[3].Data[2]=0xf1;m[3].Data[3]=0x10;
    m[4]=m[0];m[4].DataSize=13;*n=5;return 0;
}
static int utf8(unsigned cp,Dword flags,const WChar *a,int len,char *b,int n,const char *fallback,int *used){unsigned i=0;(void)flags;(void)fallback;(void)used;CHECK(cp==65001 && len==-1);while(a[i]){CHECK((int)i+1<n);b[i]=(char)a[i];i++;}b[i]=0;return i+1;}
static void *getproc(Handle h,const char *name){CHECK(h==(Handle)100);
#define MAP(n,f) if(!strcmp(name,n))return (void *)(f)
    MAP("PassThruOpen",op);MAP("PassThruClose",closefn);MAP("PassThruConnect",connectfn);MAP("PassThruDisconnect",disconnectfn);
    MAP("PassThruReadMsgs",readfn);MAP("PassThruWriteMsgs",writefn);MAP("PassThruStartMsgFilter",filterfn);MAP("PassThruIoctl",ioctlfn);MAP("PassThruGetLastError",errorfn);MAP("PassThruReadVersion",versionfn);
    return 0;
}
static LResult defproc(Handle h,unsigned m,uintptr_t w,intptr_t l){(void)h;(void)m;(void)w;(void)l;return 0;}
static void setup(void){
    path_edit=(Handle)1;rate_edit=(Handle)2;extended_check=(Handle)3;id_edit=(Handle)4;data_edit=(Handle)5;interval_edit=(Handle)6;count_edit=(Handle)7;script_edit=(Handle)8;cycles_edit=(Handle)9;
    filter_edit=(Handle)10;pause_check=(Handle)11;background_check=(Handle)12;status_label=(Handle)13;action_label=(Handle)14;monitor_edit=(Handle)15;connect_button=(Handle)16;disconnect_button=(Handle)17;
    pGetWindowTextW=gettext;pSetWindowTextW=settext;pSendMessageW=sendmsg;pEnableWindow=enable;pGetTickCount=ticks;pSleep=sleepfn;pWriteFile=writefile;pFreeLibrary=freefn;
    pLoadLibraryExW=loadex;pGetLastError=lasterrorfn;pWideCharToMultiByte=utf8;pDefWindowProcW=defproc;get_proc=getproc;
    trace_file=(Handle)1001;csv_file=(Handle)1002;
    set(path_edit,"C:\\Windows\\SysWOW64\\op20pt32.dll");set(rate_edit,"500000");set(extended_check,"0");set(id_edit,"5C1");set(data_edit,"00 00 00 60");set(interval_edit,"100");set(count_edit,"3");set(cycles_edit,"1");
}
int main(void){
    unsigned base,old_rx;setup();
    CHECK(open_adapter() && connected && !writes && filter_calls==1); /* Connect emits no CAN TX. */
    window_proc(0,0x111,130,0);CHECK(writes==1 && tx_accepted==1 && sent[0].Data[2]==5 && sent[0].Data[3]==0xc1);
    base=writes;set(data_edit,"00 11 22 33 44 55 66 77 88");manual_send(0);CHECK(writes==base);set(data_edit,"00 00 00 60");
    set(interval_edit,"1");manual_send(1);CHECK(!schedule.active && writes==base);set(interval_edit,"100");
    manual_send(1);CHECK(schedule.active);can_schedule_tick(&schedule,now);now+=100;can_schedule_tick(&schedule,now);now+=100;can_schedule_tick(&schedule,now);CHECK(!schedule.active && writes==base+3);
    set(count_edit,"0");manual_send(1);can_schedule_tick(&schedule,now);CHECK(schedule.active);base=writes;
    window_proc(0,0x111,110,0);now+=1000;can_schedule_tick(&schedule,now);CHECK(!schedule.active && writes==base);
    /* A malformed later line cannot produce an earlier valid CAN command. */
    set(script_edit,"5C1#28 00 00 60@100\n5C1#XX@100");sequence_start();CHECK(!schedule.active && writes==base);
    set(script_edit,"5C1#28 00 00 60@100\n5C1#00 00 00 60@200");sequence_start();CHECK(schedule.active);can_schedule_tick(&schedule,now);CHECK(manual_key_held);now+=100;can_schedule_tick(&schedule,now);CHECK(!schedule.active && !manual_key_held);
    wheel_click(0x28,200);CHECK(wheel_enabled);buttons_tick(&buttons,now);now+=200;buttons_tick(&buttons,now);CHECK(manual_key_held);
    base=writes;window_proc(0,0x111,110,0);CHECK(!wheel_enabled && !buttons.count && !manual_key_held && writes==base+1 && sent[writes-1].Data[4]==0);
    set(count_edit,"0");manual_send(1);CHECK(schedule.active);window_proc(0,0x1c,0,0);CHECK(!schedule.active);
    manual_send(1);set(background_check,"1");window_proc(0,0x1c,0,0);CHECK(schedule.active);stop_all(0);set(background_check,"0");
    set(filter_edit,"6DF, 5C1");apply_filter();CHECK(view_count==2 && visible_id(0x6df) && !visible_id(0x6c8));
    read_mode=4;old_rx=rx_count;receive_batch();CHECK(rx_count==old_rx+2);CHECK(strstr(csv_capture,"18DAF110") && strstr(csv_capture,"ADAPTER_STATUS"));
    set(filter_edit,"*");apply_filter();CHECK(view_count==0);set(pause_check,"1");base=monitor_count;receive_batch();CHECK(monitor_count==base);set(pause_check,"0");
    read_mode=3;receive_batch();CHECK(overflows==1 && !failed);read_mode=2;receive_batch();CHECK(failed && read_errors==1);disconnect_adapter();CHECK(!connected && !channel_open && !device_open && closes==1 && disconnects==1 && frees==1);
    /* Failed connect must release the device, without a TX. */
    connect_mode=1;base=writes;CHECK(!open_adapter() && closes==2 && frees==2 && !connected && writes==base);connect_mode=0;
    filter_mode=1;CHECK(!open_adapter() && closes==3 && disconnects==2 && writes==base);filter_mode=0;
    ioctl_mode=1;CHECK(!open_adapter() && closes==4 && disconnects==3 && writes==base);ioctl_mode=0;
    /* Extended IDs use the 29-bit flag throughout connect, filter, and TX. */
    set(extended_check,"1");set(id_edit,"18DAF110");set(data_edit,"01 02 03");CHECK(open_adapter());base=writes;manual_send(0);CHECK(writes==base+1 && sent[writes-1].TxFlags==0x100 && sent[writes-1].Data[0]==0x18);
    wheel_click(0x28,200);CHECK(!wheel_enabled && writes==base+1);
    /* Zero accepted count and write failure never become successful TX. */
    write_mode=2;base=tx_accepted;manual_send(0);CHECK(failed && tx_accepted==base && tx_failed==1);disconnect_adapter();write_mode=0;CHECK(open_adapter());
    write_mode=1;base=tx_accepted;manual_send(0);CHECK(failed && tx_accepted==base && tx_failed==2);disconnect_adapter();write_mode=0;
    CHECK(open_adapter());read_mode=1;receive_batch();CHECK(failed && read_errors==2);disconnect_adapter();
    set(extended_check,"0");set(id_edit,"5C1");set(data_edit,"28 00 00 60");CHECK(open_adapter());manual_send(0);CHECK(manual_key_held);
    log_failed=1;base=writes;stop_all(0);CHECK(writes==base+1 && !manual_key_held && sent[writes-1].Data[4]==0);log_failed=0;disconnect_adapter();
    CHECK(strstr(trace_capture,"Driver accepted zero messages") && strstr(csv_capture,"TX_FAILED") && strstr(csv_capture,"RX_OVERFLOW"));
    puts("PASS native frontend with mocked Win32/J2534: no-TX connect, GUI actions, validation, sequence atomicity, STOP/release, focus/background, RX/echo/29-bit, filters, overflow, failure cleanup and reconnect");return 0;
}
