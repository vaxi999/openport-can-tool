/* Classic CAN command panel for Windows x86 / OpenPort J2534. */
#include <stdint.h>
static void gw_zero(void *p,unsigned n){unsigned i;for(i=0;i<n;i++)((uint8_t *)p)[i]=0;}
#if !defined(__i386__) && !defined(GW_HOST_TEST)
#error Build this Windows frontend for x86; installed OpenPort DLLs are normally x86.
#endif
#ifdef GW_HOST_TEST
#define WINAPI
#else
#define WINAPI __attribute__((stdcall))
#endif
typedef uint16_t WChar;
typedef void *Handle;
typedef uint32_t Dword;
typedef int32_t Status;

/* These two entries are filled by the standard PE import loader. */
typedef Handle (WINAPI *LoadLibraryFn)(const WChar *);
typedef void *(WINAPI *GetProcFn)(Handle,const char *);
void *bootstrap_iat[3] __attribute__((section(".data")))={0,0,0};
unsigned char import_blob[256] __attribute__((section(".data")))={0};
static LoadLibraryFn load_library;
static GetProcFn get_proc;
#define API(ret,name,args) static ret (WINAPI *name) args
API(Handle,pGetStdHandle,(Dword));
API(int,pWriteFile,(Handle,const void *,Dword,Dword *,void *));
API(void,pExitProcess,(Dword));
API(Dword,pGetTickCount,(void));
API(void,pSleep,(Dword));
API(Dword,pGetModuleFileNameW,(Handle,WChar *,Dword));
API(Handle,pLoadLibraryExW,(const WChar *,Handle,Dword));
API(Handle,pCreateFileW,(const WChar *,Dword,Dword,void *,Dword,Dword,Handle));
API(int,pCloseHandle,(Handle));
API(Dword,pExpandEnvironmentStringsW,(const WChar *,WChar *,Dword));
API(int,pWideCharToMultiByte,(unsigned,Dword,const WChar *,int,char *,int,const char *,int *));
typedef struct { uint16_t year,month,weekday,day,hour,minute,second,millis; } SystemTime;
API(void,pGetLocalTime,(SystemTime *));
API(Status,pRegOpenKeyExW,(Handle,const WChar *,Dword,Dword,Handle *));
API(Status,pRegEnumKeyExW,(Handle,Dword,WChar *,Dword *,Dword *,WChar *,Dword *,void *));
API(Status,pRegQueryValueExW,(Handle,const WChar *,Dword *,Dword *,uint8_t *,Dword *));
API(Status,pRegCloseKey,(Handle));

typedef struct {
    Dword ProtocolID,RxStatus,TxFlags,Timestamp,DataSize,ExtraDataIndex;
    uint8_t Data[4128];
} PassMessage;
typedef struct { Dword Parameter,Value; } Config;
typedef struct { Dword NumOfParams; Config *ConfigPtr; } ConfigList;
typedef char VerifyJ2534MessageSize[(sizeof(PassMessage)==4152)?1:-1];
#ifndef GW_HOST_TEST
typedef char VerifyWin32PointerSize[(sizeof(void *)==4 && sizeof(ConfigList)==8)?1:-1];
#endif
API(Status,jOpen,(void *,Dword *));
API(Status,jClose,(Dword));
API(Status,jConnect,(Dword,Dword,Dword,Dword,Dword *));
API(Status,jDisconnect,(Dword));
API(Status,jRead,(Dword,PassMessage *,Dword *,Dword));
API(Status,jWrite,(Dword,PassMessage *,Dword *,Dword));
API(Status,jFilter,(Dword,Dword,PassMessage *,PassMessage *,PassMessage *,Dword *));
API(Status,jIoctl,(Dword,Dword,void *,void *));
API(Status,jLastError,(char *));
API(Status,jVersion,(Dword,char *,char *,char *));

static Handle console_out,trace_file,csv_file,window,status_label,action_label,monitor_edit;
static int log_failed;
static Dword started,device,channel;
static int device_open,channel_open;
static PassMessage tx_message,rx_messages[64],mask_message,pattern_message;
static WChar dll_path[2048],raw_dll_path[2048],log_path[2048],csv_path[2048];
static WChar reg_key[512],reg_name[512];
static char text_buffer[1024],error_buffer[256];
static unsigned string_len(const char *s) { unsigned n=0;while(s[n])n++;return n; }
static void copy_ascii_w(WChar *out,const char *in) { while(*in)*out++=(uint8_t)*in++;*out=0; }
static int valid_handle(Handle h) { return h && h!=(Handle)(uintptr_t)0xffffffffu; }
static void text(const char *s) {
    Dword n=string_len(s),written;
    if(valid_handle(console_out))pWriteFile(console_out,s,n,&written,0);
    if(valid_handle(trace_file) && (!pWriteFile(trace_file,s,n,&written,0) || written!=n))log_failed=1;
}
static void number(uint32_t v) {
    char b[12];unsigned n=0,i;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);
    for(i=0;i<n/2;i++){char c=b[i];b[i]=b[n-i-1];b[n-i-1]=c;}b[n]=0;text(b);
}
static void hex_value(uint32_t v,unsigned digits) {
    static const char hex[]="0123456789ABCDEF";char b[9];unsigned i;
    for(i=0;i<digits;i++)b[i]=hex[(v>>(4*(digits-i-1)))&15];b[digits]=0;text(b);
}
static void wide_text(const WChar *s) {
    int n=pWideCharToMultiByte(65001,0,s,-1,text_buffer,sizeof(text_buffer),0,0);
    if(n>0)text(text_buffer);else text("[path exceeds display buffer]");
}
static void error(const char *operation,Status status) {
    text("J2534 ERROR ");text(operation);text(" status=0x");hex_value((uint32_t)status,8);
    if(jLastError && jLastError(error_buffer)==0){text(" ");text(error_buffer);}text("\r\n");
}
static int has_word(const WChar *s,const char *word) {
    unsigned i,j;for(i=0;s[i];i++){
        for(j=0;word[j];j++){unsigned c=s[i+j];if(c>='A'&&c<='Z')c+=32;if(c!=(uint8_t)word[j])break;}
        if(!word[j])return 1;
    }return 0;
}
static int query_string(Handle key,const char *name,WChar *out,unsigned capacity) {
    WChar field[40];Dword type=0,size=capacity*2;copy_ascii_w(field,name);
    if(pRegQueryValueExW(key,field,0,&type,(uint8_t *)out,&size)!=0 || (type!=1 && type!=2) || size<2 || size>capacity*2)return 0;
    out[capacity-1]=0;return 1;
}
static int find_driver(void) {
    WChar root_path[80];Handle root,key;Dword index;copy_ascii_w(root_path,"SOFTWARE\\PassThruSupport.04.04");
    if(pRegOpenKeyExW((Handle)(uintptr_t)0x80000002u,root_path,0,0x20019,&root)!=0)return 0;
    for(index=0;index<256;index++) {
        Dword length=511;Status status=pRegEnumKeyExW(root,index,reg_key,&length,0,0,0,0);
        if(status==259)break;if(status)continue;reg_key[511]=0;
        if(pRegOpenKeyExW(root,reg_key,0,0x20019,&key)!=0)continue;
        reg_name[0]=0;(void)query_string(key,"Name",reg_name,512);
        if((has_word(reg_key,"openport")||has_word(reg_key,"tactrix")||has_word(reg_name,"openport")||has_word(reg_name,"tactrix"))
           && query_string(key,"FunctionLibrary",raw_dll_path,2048)) {
            Dword expanded=pExpandEnvironmentStringsW(raw_dll_path,dll_path,2048);
            pRegCloseKey(key);pRegCloseKey(root);
            if(!expanded || expanded>2048)return 0;
            text("J2534 provider: ");wide_text(reg_key);text("\r\nDLL: ");wide_text(dll_path);text("\r\n");return 1;
        }
        pRegCloseKey(key);
    }
    pRegCloseKey(root);return 0;
}
static void make_log(void) {
    SystemTime t;unsigned i,n;char suffix[80];char *p=suffix;uint16_t v[7];
    n=pGetModuleFileNameW(0,log_path,1900);if(n==0 || n>=1900){log_path[0]=0;n=0;}
    while(n && log_path[n-1]!='\\' && log_path[n-1]!='/')n--;log_path[n]=0;
    pGetLocalTime(&t);v[0]=t.year;v[1]=t.month;v[2]=t.day;v[3]=t.hour;v[4]=t.minute;v[5]=t.second;v[6]=t.millis;
    {const char *s="LOG_TEST_TABLE_";while(*s)*p++=*s++;}
    for(i=0;i<7;i++) {
        if(i==3 || i==6)*p++='_';if(i==6)*p++=(char)('0'+v[i]/100);
        if(i==0){*p++=(char)('0'+v[i]/1000);*p++=(char)('0'+(v[i]/100)%10);}
        *p++=(char)('0'+(v[i]/10)%10);*p++=(char)('0'+v[i]%10);
    }
    {const char *s=".txt";while(*s)*p++=*s++;}*p=0;
    for(i=0;suffix[i];i++)log_path[n+i]=(uint8_t)suffix[i];log_path[n+i]=0;
    trace_file=pCreateFileW(log_path,0x40000000u,1,0,1,0x80,0);
    if(!valid_handle(trace_file)){log_failed=1;return;}
    for(i=0;log_path[i];i++)csv_path[i]=log_path[i];
    csv_path[i]=0;csv_path[i-3]='c';csv_path[i-2]='s';csv_path[i-1]='v';
    csv_file=pCreateFileW(csv_path,0x40000000u,1,0,1,0x80,0);
    if(!valid_handle(csv_file)){log_failed=1;return;}
    {const char *h="host_ms,adapter_us,dir,can_id,dlc,data,flags_or_error\r\n";Dword n=string_len(h),w;
     if(!pWriteFile(csv_file,h,n,&w,0) || w!=n)log_failed=1;}
}

#include "buttons_core.h"
#include "sender_core.h"
typedef intptr_t LResult;
typedef LResult (WINAPI *WindowProc)(Handle,unsigned,uintptr_t,intptr_t);
typedef struct {Dword size,style;WindowProc proc;int class_extra,window_extra;Handle instance,icon,cursor,background;const WChar *menu,*name;Handle small_icon;} WindowClass;
typedef struct {Handle hwnd;unsigned message;uintptr_t wparam;intptr_t lparam;Dword time;int x,y;Dword private_data;} WinMessage;
#ifndef GW_HOST_TEST
typedef char VerifyWindowClassSize[(sizeof(WindowClass)==48)?1:-1];
typedef char VerifyWinMessageSize[(sizeof(WinMessage)==32)?1:-1];
#endif
API(unsigned short,pRegisterClassExW,(const WindowClass *));
API(Handle,pCreateWindowExW,(Dword,const WChar *,const WChar *,Dword,int,int,int,int,Handle,Handle,Handle,void *));
API(LResult,pDefWindowProcW,(Handle,unsigned,uintptr_t,intptr_t));
API(int,pPeekMessageW,(WinMessage *,Handle,unsigned,unsigned,unsigned));
API(int,pTranslateMessage,(const WinMessage *));
API(LResult,pDispatchMessageW,(const WinMessage *));
API(int,pShowWindow,(Handle,int));
API(int,pUpdateWindow,(Handle));
API(int,pSetWindowTextW,(Handle,const WChar *));
API(int,pMessageBoxW,(Handle,const WChar *,const WChar *,unsigned));
API(Handle,pLoadCursorW,(Handle,const WChar *));
API(Handle,pGetModuleHandleW,(const WChar *));
API(LResult,pSendMessageW,(Handle,unsigned,uintptr_t,intptr_t));
API(Handle,pGetStockObject,(int));
API(int,pFlushFileBuffers,(Handle));
API(int,pDestroyWindow,(Handle));
API(int,pGetWindowTextW,(Handle,WChar *,int));
API(int,pEnableWindow,(Handle,int));
API(int,pFreeLibrary,(Handle));
API(int,pReadFile,(Handle,void *,Dword,Dword *,void *));
API(Dword,pGetLastError,(void));

static Buttons buttons;
static CanSchedule schedule;
static int running=1,connected,failed,wheel_enabled,manual_key_held,exit_code,release_attempt;
static unsigned tx_accepted,tx_failed,rx_count,read_errors,overflows;
static Dword last_flush,last_status,bitrate=500000;
static unsigned extended;
static Handle driver_dll,path_edit,rate_edit,extended_check,connect_button,disconnect_button;
static Handle id_edit,data_edit,interval_edit,count_edit,script_edit,cycles_edit;
static Handle filter_edit,pause_check,background_check;
static uint32_t view_ids[32];static unsigned view_count;
static char monitor_lines[96][144];static unsigned monitor_next,monitor_count,monitor_dirty;
static WChar monitor_wide[14500],input_wide[22000];
static char script_text[22000],input_buffer[22000],status_buffer[512];
static const char example_script[]="; OK click, then release\r\n5C1#28 00 00 60@100\r\n5C1#28 00 00 60@100\r\n5C1#00 00 00 60@100\r\n5C1#00 00 00 60@200";

static void caption(Handle h,const char *s){WChar out[1024];unsigned i;for(i=0;i<1023 && s[i];i++)out[i]=(uint8_t)s[i];out[i]=0;pSetWindowTextW(h,out);}
static char *append(char *p,const char *s){while(*s)*p++=*s++;return p;}
static char *decimal(char *p,uint32_t value){char t[12];unsigned n=0;do{t[n++]=(char)('0'+value%10);value/=10;}while(value);while(n)*p++=t[--n];return p;}
static char *hexbuf(char *p,uint32_t value,unsigned digits){static const char h[]="0123456789ABCDEF";unsigned i;for(i=0;i<digits;i++)*p++=h[(value>>(4*(digits-1-i)))&15];return p;}
static int get_ascii(Handle h,char *out,unsigned capacity){
    unsigned i;int n;if(capacity>22000)return 0;
    n=pGetWindowTextW(h,input_wide,(int)capacity);if(n<0 || (unsigned)n>=capacity-1)return 0;
    for(i=0;i<(unsigned)n;i++){if(input_wide[i]>127)return 0;out[i]=(char)input_wide[i];}out[i]=0;return 1;
}
static void action_note(const char *s){text("ACTION ");number(pGetTickCount()-started);text(" ms ");text(s);text("\r\n");if(action_label)caption(action_label,s);}
static void csv_frame(const char *direction,Dword id,const uint8_t *data,unsigned n,Dword stamp,Dword flags){
    char line[200],*p=line;Dword bytes,w;unsigned i;
    p=decimal(p,pGetTickCount()-started);*p++=',';p=decimal(p,stamp);*p++=',';
    p=append(p,direction);*p++=',';p=hexbuf(p,id,id>0x7ff?8:3);*p++=',';p=decimal(p,n);*p++=',';
    for(i=0;i<n && i<8;i++){if(i)*p++=' ';p=hexbuf(p,data[i],2);}*p++=',';p=hexbuf(p,flags,8);*p++='\r';*p++='\n';bytes=(Dword)(p-line);
    if(valid_handle(csv_file) && (!pWriteFile(csv_file,line,bytes,&w,0) || w!=bytes))log_failed=1;
}
static int visible_id(Dword id){unsigned i;if(!view_count)return 1;for(i=0;i<view_count;i++)if(view_ids[i]==id)return 1;return 0;}
static void monitor_frame(const char *dir,const CanFrame *f,Dword stamp){
    char *p;unsigned i;if(!visible_id(f->id))return;
    if(pause_check && pSendMessageW(pause_check,0xf0,0,0)==1)return;
    p=monitor_lines[monitor_next];p=decimal(p,pGetTickCount()-started);p=append(p," ms  ");p=append(p,dir);
    p=append(p,f->extended?"  EXT ":"  STD ");p=hexbuf(p,f->id,f->extended?8:3);p=append(p,"  [");p=decimal(p,f->size);p=append(p,"]  ");
    for(i=0;i<f->size;i++){if(i)*p++=' ';p=hexbuf(p,f->data[i],2);}
    if(dir[0]=='R'){p=append(p,"  us=");p=decimal(p,stamp);}*p=0;
    monitor_next=(monitor_next+1)%96;if(monitor_count<96)monitor_count++;monitor_dirty=1;
}
static void refresh_monitor(void){
    unsigned i,j,at=0,index;if(!monitor_dirty || !monitor_edit)return;
    for(i=0;i<monitor_count;i++){index=(monitor_next+96-monitor_count+i)%96;
        for(j=0;monitor_lines[index][j] && at<14490;j++)monitor_wide[at++]=(uint8_t)monitor_lines[index][j];
        monitor_wide[at++]='\r';monitor_wide[at++]='\n';}
    monitor_wide[at]=0;pSetWindowTextW(monitor_edit,monitor_wide);
    pSendMessageW(monitor_edit,0xb1,(uintptr_t)-1,(intptr_t)-1);pSendMessageW(monitor_edit,0xb7,0,0);monitor_dirty=0;
}
static int send_frame(void *unused,const CanFrame *f){
    Dword n=1;Status s;unsigned i;(void)unused;
    if(!channel_open || f->size>8 || f->extended!=extended || f->id>(extended?0x1fffffffu:0x7ffu))return -1;
    gw_zero(&tx_message,sizeof(tx_message));tx_message.ProtocolID=5;tx_message.TxFlags=f->extended?0x100u:0;
    tx_message.DataSize=4+f->size;tx_message.ExtraDataIndex=tx_message.DataSize;
    for(i=0;i<4;i++)tx_message.Data[i]=(uint8_t)(f->id>>(8*(3-i)));
    for(i=0;i<f->size;i++)tx_message.Data[4+i]=f->data[i];
    csv_frame("TX_REQUEST",f->id,f->data,f->size,0,tx_message.TxFlags);
    if(log_failed && !release_attempt)return -1;
    s=jWrite(channel,&tx_message,&n,100);
    if(s || n!=1){tx_failed++;csv_frame("TX_FAILED",f->id,f->data,f->size,0,(Dword)s);error("PassThruWriteMsgs",s);if(!s)text("Driver accepted zero messages.\r\n");failed=1;return -1;}
    tx_accepted++;csv_frame("TX_ACCEPTED",f->id,f->data,f->size,0,tx_message.TxFlags);monitor_frame("TX OK",f,0);
    if(!f->extended && f->id==0x5c1 && f->size==4 && !f->data[1] && !f->data[2] && f->data[3]==0x60 && button_key_allowed(f->data[0]))manual_key_held=f->data[0]!=0;
    return 0;
}
static int send_button(void *unused,uint8_t key){
    CanFrame f;int result;(void)unused;if(extended || !button_key_allowed(key))return -1;
    gw_zero(&f,sizeof(f));f.id=0x5c1;f.size=4;f.data[0]=key;f.data[3]=0x60;
    release_attempt=key==0;result=send_frame(0,&f);release_attempt=0;return result;
}
static void stop_all(const char *reason){
    can_schedule_stop(&schedule);
    if(channel_open && (wheel_enabled || manual_key_held))buttons_cancel(&buttons,pGetTickCount());
    buttons.active=0;buttons.count=0;wheel_enabled=0;manual_key_held=0;
    if(reason)action_note(reason);
}
static void receive_batch(void){
    Dword n=64;Status s;unsigned i,k;
    s=jRead(channel,rx_messages,&n,0);
    if(n>64){read_errors++;action_note("The driver returned an invalid RX message count.");failed=1;return;}
    if(s==16)return;
    if(s==0x12){overflows++;text("RX BUFFER OVERFLOW: data loss in capture.\r\n");csv_frame("RX_OVERFLOW",0,0,0,0,(Dword)s);}
    else if(s && s!=9){read_errors++;error("PassThruReadMsgs",s);failed=1;return;}
    for(i=0;i<n;i++){
        PassMessage *m=&rx_messages[i];CanFrame f;
        if(m->ProtocolID!=5 || m->DataSize<4 || m->DataSize>12)continue;
        f.id=0;for(k=0;k<4;k++)f.id=(f.id<<8)|m->Data[k];f.size=m->DataSize-4;f.extended=(m->RxStatus&0x100u)?1:0;
        if(f.id>(f.extended?0x1fffffffu:0x7ffu))continue;
        for(k=0;k<f.size;k++)f.data[k]=m->Data[4+k];
        if(m->RxStatus&9u){csv_frame("ADAPTER_STATUS",f.id,f.data,f.size,m->Timestamp,m->RxStatus);continue;}
        rx_count++;csv_frame("RX",f.id,f.data,f.size,m->Timestamp,m->RxStatus);monitor_frame("RX",&f,m->Timestamp);
    }
}
static void update_status(void){
    char *p=status_buffer;
    p=append(p,connected?"CONNECTED | ":"DISCONNECTED | ");p=decimal(p,bitrate);p=append(p,extended?" bit/s | 29-bit":" bit/s | 11-bit");
    p=append(p," | TX accepted: ");p=decimal(p,tx_accepted);p=append(p," | RX: ");p=decimal(p,rx_count);p=append(p," | TX errors: ");p=decimal(p,tx_failed);
    p=append(p,"\r\nSending: ");p=append(p,schedule.active?"REPEAT/SEQUENCE":wheel_enabled?"STEERING":"STOPPED");
    p=append(p," | Completed cycles: ");p=decimal(p,schedule.completed);p=append(p," | Lost RX blocks: ");p=decimal(p,overflows);
    if(log_failed)p=append(p," | LOG ERROR");else if(failed)p=append(p," | DRIVER ERROR");
    *p=0;caption(status_label,status_buffer);refresh_monitor();
}
static void set_connection_controls(void){
    pEnableWindow(path_edit,!connected);pEnableWindow(rate_edit,!connected);pEnableWindow(extended_check,!connected);
    pEnableWindow(connect_button,!connected && !log_failed);pEnableWindow(disconnect_button,connected);
}
static int can_operate(void){if(!connected || failed || log_failed){action_note("Connect OpenPort first. Check the TXT log if connection fails.");return 0;}return 1;}
static void wheel_click(unsigned key,unsigned duration){
    if(!can_operate())return;if(extended){action_note("The steering profile uses 11-bit CAN. Disconnect and disable 29-bit mode.");return;}
    if(schedule.active)stop_all(0);
    if(!wheel_enabled){buttons_init(&buttons,send_button,0,pGetTickCount());wheel_enabled=1;}
    if(buttons_enqueue(&buttons,key,duration))action_note("STEERING: click queued. STOP releases the button and stops neutral frames.");else action_note("The click queue is full.");
}
static void manual_send(unsigned repeating){
    CanFrame f;char id[40],data[100],ntext[32];uint32_t period=100,limit=1;
    if(!can_operate())return;
    if(!get_ascii(id_edit,id,sizeof(id)) || !get_ascii(data_edit,data,sizeof(data)) || !can_frame(id,data,extended,&f)){
        action_note("Invalid CAN ID or HEX data. Maximum 8 bytes, two HEX digits per byte.");return;}
    if(repeating){
        if(!get_ascii(interval_edit,ntext,sizeof(ntext)) || !can_uint(ntext,60000,&period) || period<20){action_note("Interval must be between 20 and 60000 ms.");return;}
        if(!get_ascii(count_edit,ntext,sizeof(ntext)) || !can_uint(ntext,1000000,&limit)){action_note("Repeat count: 1 to 1000000, or 0 for continuous sending.");return;}
    }
    stop_all(0);
    if(!repeating){if(send_frame(0,&f)==0)action_note("OpenPort accepted the command. Monitor RX and the cluster response.");return;}
    schedule.steps[0].frame=f;schedule.steps[0].delay=period;can_schedule_start(&schedule,1,limit,pGetTickCount(),send_frame,0);
    action_note("Repeat started. STOP ends transmission.");
}
static void sequence_start(void){
    unsigned count,line;uint32_t limit;char cycles[32],message[100],*p;
    if(!can_operate())return;
    /* An old schedule must not keep using partially replaced steps. */
    stop_all(0);
    if(!get_ascii(script_edit,script_text,sizeof(script_text)) || !get_ascii(cycles_edit,cycles,sizeof(cycles)) || !can_uint(cycles,1000000,&limit)){
        action_note("Sequence must be ASCII HEX text. Cycles: 0 to 1000000.");return;}
    if(!can_script(script_text,extended,schedule.steps,&count,&line)){
        p=append(message,"Sequence error on line ");p=decimal(p,line);p=append(p,". Format: 5C1#28 00 00 60@100");*p=0;action_note(message);return;
    }
    can_schedule_start(&schedule,count,limit,pGetTickCount(),send_frame,0);action_note("Sequence started. All lines were validated before sending.");
}
static void apply_filter(void){
    char raw[300],one[40];uint32_t ids[32];unsigned i=0,j,n=0,k;
    if(!get_ascii(filter_edit,raw,sizeof(raw))){action_note("Filter: enter comma-separated HEX IDs or *.");return;}
    while(can_space(raw[i]))i++;
    if(!raw[i] || (raw[i]=='*' && !raw[i+1])){view_count=0;monitor_count=monitor_next=0;monitor_dirty=1;action_note("Display: all IDs. CSV always records all received frames.");return;}
    while(raw[i]){
        j=0;while(raw[i] && raw[i]!=','){if(j+1>=sizeof(one))goto invalid;one[j++]=raw[i++];}one[j]=0;
        if(n==32 || !can_id(one,1,&ids[n++]))goto invalid;
        if(raw[i]==','){i++;if(!raw[i])goto invalid;}
    }
    for(k=0;k<n;k++)view_ids[k]=ids[k];view_count=n;monitor_count=monitor_next=0;monitor_dirty=1;action_note("Display filter applied. CSV still records all RX.");return;
invalid:action_note("Invalid filter. Example: 5C1,6C8,6DF. Enter * for all IDs.");
}
static int sibling_path(WChar *out,const char *name){
    unsigned n=pGetModuleFileNameW(0,out,1900),i;if(!n || n>=1900)return 0;
    while(n && out[n-1]!='\\' && out[n-1]!='/')n--;
    for(i=0;name[i] && n+i<2047;i++)out[n+i]=(uint8_t)name[i];out[n+i]=0;return !name[i];
}
static void sequence_file(unsigned saving){
    WChar path[2048];Handle file;Dword n,w;unsigned i,start=0;
    if(!sibling_path(path,"SEKVENCA.txt"))return;
    if(saving){
        if(!get_ascii(script_edit,input_buffer,sizeof(input_buffer))){action_note("The sequence to save must be ASCII HEX text.");return;}
        file=pCreateFileW(path,0x40000000u,1,0,2,0x80,0); /* CREATE_ALWAYS */
        if(!valid_handle(file)){action_note("SEKVENCA.txt could not be saved.");return;}
        n=string_len(input_buffer);i=pWriteFile(file,input_buffer,n,&w,0) && w==n;pCloseHandle(file);
        action_note(i?"Saved to SEKVENCA.txt beside the executable.":"Error writing SEKVENCA.txt.");return;
    }
    file=pCreateFileW(path,0x80000000u,1,0,3,0x80,0);
    if(!valid_handle(file)){action_note("SEKVENCA.txt was not found beside the executable.");return;}
    i=pReadFile(file,input_buffer,sizeof(input_buffer)-1,&n,0);pCloseHandle(file);
    if(!i || n>=sizeof(input_buffer)-1){action_note("SEKVENCA.txt is too large or cannot be read.");return;}
    if(n>=3 && (uint8_t)input_buffer[0]==0xef && (uint8_t)input_buffer[1]==0xbb && (uint8_t)input_buffer[2]==0xbf)start=3;
    for(i=start;i<n;i++)if((uint8_t)input_buffer[i]>127 || !input_buffer[i]){action_note("SEKVENCA.txt must contain ASCII HEX text (UTF-8 without non-ASCII characters).");return;}
    for(i=start;i<n;i++)input_wide[i-start]=(uint8_t)input_buffer[i];input_wide[n-start]=0;pSetWindowTextW(script_edit,input_wide);
    action_note("SEKVENCA.txt loaded. No frames were sent.");
}

#define BIND(target,module,name) do { *(void **)(&(target))=get_proc((module),(name));if(!(target))return 0; } while(0)
static int bind_driver(Handle dll){
    BIND(jOpen,dll,"PassThruOpen");BIND(jClose,dll,"PassThruClose");BIND(jConnect,dll,"PassThruConnect");BIND(jDisconnect,dll,"PassThruDisconnect");
    BIND(jRead,dll,"PassThruReadMsgs");BIND(jWrite,dll,"PassThruWriteMsgs");BIND(jFilter,dll,"PassThruStartMsgFilter");BIND(jIoctl,dll,"PassThruIoctl");BIND(jLastError,dll,"PassThruGetLastError");
    *(void **)(&jVersion)=get_proc(dll,"PassThruReadVersion");return 1;
}
static void disconnect_adapter(void){
    stop_all(0);
    if(channel_open){Status s=jDisconnect(channel);if(s)error("PassThruDisconnect",s);channel_open=0;}
    if(device_open){Status s=jClose(device);if(s)error("PassThruClose",s);device_open=0;}
    if(driver_dll){pFreeLibrary(driver_dll);driver_dll=0;}connected=0;set_connection_controls();
}
static int open_adapter(void){
    Status s;Config cfg;ConfigList list;Dword filter;char fw[256],driver[256],api[256],rate[40];
    if(connected)return 1;if(log_failed){action_note("Log unavailable. Extract the ZIP to a writable folder.");return 0;}
    if(!get_ascii(rate_edit,rate,sizeof(rate)) || !can_uint(rate,1000000,&bitrate) || bitrate<10000){action_note("CAN bitrate must be between 10000 and 1000000 bit/s.");return 0;}
    extended=pSendMessageW(extended_check,0xf0,0,0)==1;
    if(pGetWindowTextW(path_edit,dll_path,2048)<=0){action_note("DLL not found. Enter the full path to op20pt32.dll.");return 0;}
    dll_path[2047]=0;text("CONNECT DLL: ");wide_text(dll_path);text("\r\nCAN bitrate=");number(bitrate);text(" extended=");number(extended);text(" pins=6/14\r\n");
    driver_dll=pLoadLibraryExW(dll_path,0,8);
    if(!driver_dll){text("Win32 LoadLibrary error=");number(pGetLastError());text("\r\n");action_note("Cannot load DLL. An x86 OpenPort DLL and installed driver are required.");return 0;}
    if(!bind_driver(driver_dll)){action_note("The selected DLL lacks required J2534 functions.");goto bad;}
    s=jOpen(0,&device);if(s){error("PassThruOpen",s);action_note("Cannot open OpenPort. Close ODIS/VCDS/VCP and other capture tools.");goto bad;}device_open=1;
    if(jVersion && !jVersion(device,fw,driver,api)){fw[255]=driver[255]=api[255]=0;text("FW: ");text(fw);text("\r\nDriver: ");text(driver);text("\r\nAPI: ");text(api);text("\r\n");}
    s=jConnect(device,5,extended?0x100:0,bitrate,&channel);if(s){error("PassThruConnect",s);action_note("Cannot open CAN connection. Check the bitrate and TXT log.");goto bad;}channel_open=1;
    cfg.Parameter=3;cfg.Value=0;list.NumOfParams=1;list.ConfigPtr=&cfg;
    s=jIoctl(channel,2,&list,0);if(s){error("SET_CONFIG LOOPBACK=0",s);goto configbad;}
    gw_zero(&mask_message,sizeof(mask_message));gw_zero(&pattern_message,sizeof(pattern_message));
    mask_message.ProtocolID=pattern_message.ProtocolID=5;mask_message.DataSize=pattern_message.DataSize=4;
    mask_message.ExtraDataIndex=pattern_message.ExtraDataIndex=4;mask_message.TxFlags=pattern_message.TxFlags=extended?0x100:0;
    s=jFilter(channel,1,&mask_message,&pattern_message,0,&filter);if(s){error("PassThruStartMsgFilter",s);goto configbad;}
    s=jIoctl(channel,8,0,0);if(s){error("CLEAR_RX_BUFFER",s);goto configbad;}
    failed=0;connected=1;buttons_init(&buttons,send_button,0,pGetTickCount());set_connection_controls();
    action_note("Connected. Transmission is stopped; select a command or steering button.");return 1;
configbad:action_note("J2534 channel configuration failed. See the TXT log.");
bad:disconnect_adapter();return 0;
}
static LResult WINAPI window_proc(Handle hwnd,unsigned msg,uintptr_t wp,intptr_t lp){
    if(msg==0x111 && (wp>>16)==0){switch(wp&0xffff){
        case 101:wheel_click(9,200);break;case 102:wheel_click(0x22,200);break;case 103:wheel_click(10,200);break;
        case 104:wheel_click(0x29,200);break;case 105:wheel_click(0x28,200);break;case 106:wheel_click(0x23,200);break;
        case 107:wheel_click(0x22,2000);break;case 108:wheel_click(0x28,2000);break;case 109:wheel_click(0x29,2000);break;
        case 110:stop_all("STOP: transmission stopped; active button released if applicable.");break;
        case 111:running=0;break;case 120:open_adapter();break;
        case 121:disconnect_adapter();action_note("Disconnected.");break;
        case 130:manual_send(0);break;case 131:manual_send(1);break;case 132:sequence_start();break;
        case 133:apply_filter();break;
        case 134:monitor_count=monitor_next=0;monitor_dirty=1;refresh_monitor();break;
        case 135:sequence_file(1);break;case 136:sequence_file(0);break;
        }return 0;}
    if(msg==0x1c && !wp && connected && pSendMessageW(background_check,0xf0,0,0)!=1){
        if(schedule.active || wheel_enabled || manual_key_held)stop_all("STOP: window lost focus. Enable background sending to continue.");return 0;}
    if(msg==0x10 || msg==2){running=0;return 0;}
    return pDefWindowProcW(hwnd,msg,wp,lp);
}
static Handle control(const char *type,const char *label,int x,int y,int w,int h,unsigned id,Dword extra){
    WChar cls[32],txt[512];Handle result;copy_ascii_w(cls,type);copy_ascii_w(txt,label);
    result=pCreateWindowExW(0,cls,txt,0x50000000u|(id?0x10000u:0)|extra,x,y,w,h,window,(Handle)(uintptr_t)id,pGetModuleHandleW(0),0);
    if(result)pSendMessageW(result,0x30,(uintptr_t)pGetStockObject(17),1);return result;
}
static int make_window(void){
    WindowClass wc;WChar name[64],title[80];unsigned i;
    static const char *labels[]={"< LEFT","UP ^","RIGHT >","BACK","OK","DOWN v","UP 2 s","OK 2 s","BACK 2 s"};
    copy_ascii_w(name,"OpenPortTestTableV1");copy_ascii_w(title,"OpenPort - instrument cluster test / CAN commands V1");
    gw_zero(&wc,sizeof(wc));wc.size=sizeof(wc);wc.proc=window_proc;wc.instance=pGetModuleHandleW(0);wc.name=name;
    wc.cursor=pLoadCursorW(0,(const WChar *)(uintptr_t)32512);wc.background=(Handle)16;
    if(!pRegisterClassExW(&wc))return 0;
    window=pCreateWindowExW(0,name,title,0x00ca0000u,0x80000000u,0x80000000u,1000,740,0,0,wc.instance,0);if(!window)return 0;
    status_label=control("STATIC","DISCONNECTED",16,12,950,42,0,0);
    control("STATIC","J2534 DLL:",16,62,90,22,0,0);path_edit=control("EDIT","",106,58,860,25,200,0x00800080u);
    if(find_driver())pSetWindowTextW(path_edit,dll_path);else caption(path_edit,"C:\\Windows\\SysWOW64\\op20pt32.dll");
    control("STATIC","CAN bit/s:",16,96,80,22,0,0);rate_edit=control("EDIT","500000",96,91,100,26,201,0x00800080u);
    extended_check=control("BUTTON","29-bit ID",210,91,110,26,202,3);
    connect_button=control("BUTTON","CONNECT",334,90,100,28,120,0);disconnect_button=control("BUTTON","DISCONNECT",444,90,130,28,121,0);
    background_check=control("BUTTON","Keep sending in background",600,91,225,26,203,3);
    control("BUTTON","STOP ALL",836,90,130,28,110,0);
    control("STATIC","MANUAL CAN FRAME  |  HEX ID and data; maximum 8 bytes",16,130,640,22,0,0);
    control("STATIC","CAN ID",16,158,65,22,0,0);id_edit=control("EDIT","5C1",83,154,100,26,204,0x00800080u);
    control("STATIC","Data",202,158,60,22,0,0);data_edit=control("EDIT","00 00 00 60",266,154,410,26,205,0x00800080u);
    control("BUTTON","SEND ONCE",696,153,130,28,130,0);
    control("STATIC","Interval ms",16,193,80,22,0,0);interval_edit=control("EDIT","100",100,188,82,26,206,0x00800080u);
    control("STATIC","Repeats (0=continuous)",201,193,160,22,0,0);count_edit=control("EDIT","10",365,188,95,26,207,0x00800080u);
    control("BUTTON","REPEAT",480,187,150,29,131,0);
    control("STATIC","TX accepted means driver acceptance.",646,194,320,22,0,0);
    control("STATIC","SEQUENCE  |  ID#HEX@delay_ms  |  ; comment  |  up to 128 lines",16,232,640,22,0,0);
    script_edit=control("EDIT","",16,258,610,122,208,0x00a010c4u);
    copy_ascii_w(input_wide,example_script);pSetWindowTextW(script_edit,input_wide);pSendMessageW(script_edit,0xc5,21000,0);
    control("STATIC","Cycles (0=continuous)",16,392,125,22,0,0);cycles_edit=control("EDIT","1",143,387,80,27,209,0x00800080u);
    control("BUTTON","RUN SEQUENCE",235,386,170,29,132,0);
    control("BUTTON","SAVE",416,386,98,29,135,0);control("BUTTON","LOAD",526,386,100,29,136,0);
    control("STATIC","STEERING / CLUSTER MENU  |  5C1 profile",654,232,312,22,0,0);
    for(i=0;i<9;i++)if(!control("BUTTON",labels[i],654+(i%3)*106,258+(i/3)*39,100,33,101+i,0))return 0;
    control("STATIC","Click 200 ms. Long press 2 s.\r\nSTOP ends sending and releases.",654,381,312,40,0,0);
    control("STATIC","RX/TX MONITOR  |  ID filter:",16,434,220,22,0,0);filter_edit=control("EDIT","*",240,430,240,26,210,0x00800080u);
    control("BUTTON","APPLY",491,430,105,27,133,0);pause_check=control("BUTTON","Pause display",608,430,155,27,211,3);
    control("BUTTON","CLEAR DISPLAY",782,430,184,27,134,0);
    monitor_edit=control("EDIT","",16,468,950,160,212,0x00a008c4u);pSendMessageW(monitor_edit,0xc5,14499,0);
    action_label=control("STATIC","Connect OpenPort; sending starts only when you select a command.",16,642,950,32,0,0);
    control("STATIC","RAW CAN on pins 6/14. TXT/CSV saved beside EXE. Esc = STOP. Uses the installed OpenPort driver.",16,679,950,22,0,0);
    if(!status_label || !action_label || !script_edit || !monitor_edit || !data_edit || !path_edit)return 0;
    set_connection_controls();pShowWindow(window,5);pUpdateWindow(window);return 1;
}
static int bind_windows(void){
    WChar name[32];Handle k,r,u,g;load_library=(LoadLibraryFn)bootstrap_iat[0];get_proc=(GetProcFn)bootstrap_iat[1];
    copy_ascii_w(name,"kernel32.dll");k=load_library(name);if(!k)return 0;
    BIND(pExitProcess,k,"ExitProcess");BIND(pGetStdHandle,k,"GetStdHandle");BIND(pWriteFile,k,"WriteFile");BIND(pReadFile,k,"ReadFile");
    BIND(pGetTickCount,k,"GetTickCount");BIND(pSleep,k,"Sleep");BIND(pGetModuleFileNameW,k,"GetModuleFileNameW");
    BIND(pCreateFileW,k,"CreateFileW");BIND(pLoadLibraryExW,k,"LoadLibraryExW");BIND(pCloseHandle,k,"CloseHandle");
    BIND(pExpandEnvironmentStringsW,k,"ExpandEnvironmentStringsW");BIND(pWideCharToMultiByte,k,"WideCharToMultiByte");
    BIND(pGetLocalTime,k,"GetLocalTime");BIND(pFlushFileBuffers,k,"FlushFileBuffers");BIND(pGetModuleHandleW,k,"GetModuleHandleW");
    BIND(pFreeLibrary,k,"FreeLibrary");BIND(pGetLastError,k,"GetLastError");
    copy_ascii_w(name,"advapi32.dll");r=load_library(name);if(!r)return 0;
    BIND(pRegOpenKeyExW,r,"RegOpenKeyExW");BIND(pRegEnumKeyExW,r,"RegEnumKeyExW");BIND(pRegQueryValueExW,r,"RegQueryValueExW");BIND(pRegCloseKey,r,"RegCloseKey");
    copy_ascii_w(name,"user32.dll");u=load_library(name);if(!u)return 0;
    BIND(pRegisterClassExW,u,"RegisterClassExW");BIND(pCreateWindowExW,u,"CreateWindowExW");BIND(pDefWindowProcW,u,"DefWindowProcW");
    BIND(pPeekMessageW,u,"PeekMessageW");BIND(pTranslateMessage,u,"TranslateMessage");BIND(pDispatchMessageW,u,"DispatchMessageW");
    BIND(pShowWindow,u,"ShowWindow");BIND(pUpdateWindow,u,"UpdateWindow");BIND(pSetWindowTextW,u,"SetWindowTextW");BIND(pGetWindowTextW,u,"GetWindowTextW");
    BIND(pEnableWindow,u,"EnableWindow");BIND(pMessageBoxW,u,"MessageBoxW");BIND(pLoadCursorW,u,"LoadCursorW");BIND(pSendMessageW,u,"SendMessageW");BIND(pDestroyWindow,u,"DestroyWindow");
    copy_ascii_w(name,"gdi32.dll");g=load_library(name);if(!g)return 0;BIND(pGetStockObject,g,"GetStockObject");return 1;
}
void entry(void){
    WinMessage msg;unsigned processed;
    if(!bind_windows()){if(pExitProcess)pExitProcess(2);return;}
    started=pGetTickCount();make_log();
    if(!make_window()){exit_code=2;goto done;}
    text("OPENPORT TEST TABLE V1 / 21.10.2026\r\nRAW classic CAN panel. Default 500000 bit/s, 11-bit IDs, OBD pins 6/14.\r\nNo automatic TX on launch or connect. Commands start only after an explicit GUI action.\r\nTX_ACCEPTED is driver acceptance, not proof of ECU response or LCD behavior.\r\n");
    if(log_failed)action_note("Cannot create log. Extract the ZIP to a writable folder.");
    last_flush=last_status=pGetTickCount();update_status();
    while(running){
        processed=0;while(processed++<64 && pPeekMessageW(&msg,0,0,0,1)){
            if(msg.message==0x12){running=0;break;}
            if(msg.message==0x100 && msg.wparam==27){stop_all("Keyboard STOP.");continue;}
            pTranslateMessage(&msg);pDispatchMessageW(&msg);if(!running)break;
        }
        if(!running)break;
        if(connected && !failed && !log_failed){
            if(schedule.active)can_schedule_tick(&schedule,pGetTickCount());
            if(wheel_enabled && !failed && !log_failed)buttons_tick(&buttons,pGetTickCount());
            if(!failed && !log_failed)receive_batch();
            if(buttons.fault)failed=1;
        }
        if(connected && (failed || log_failed)){
            disconnect_adapter();exit_code=1;action_note("ERROR: transmission and connection stopped. See TXT/CSV. You can reconnect.");
        }
        if(pGetTickCount()-last_status>=200){update_status();last_status=pGetTickCount();}
        if(pGetTickCount()-last_flush>=1000){
            if(valid_handle(trace_file) && !pFlushFileBuffers(trace_file))log_failed=1;
            if(valid_handle(csv_file) && !pFlushFileBuffers(csv_file))log_failed=1;last_flush=pGetTickCount();
        }
        pSleep(5);
    }
done:
    disconnect_adapter();text("SUMMARY TX_ACCEPTED=");number(tx_accepted);text(" TX_FAILED=");number(tx_failed);text(" RX=");number(rx_count);
    text(" READ_ERRORS=");number(read_errors);text(" RX_OVERFLOWS=");number(overflows);text("\r\nFINISHED\r\n");
    if(valid_handle(trace_file)){pFlushFileBuffers(trace_file);pCloseHandle(trace_file);trace_file=0;}
    if(valid_handle(csv_file)){pFlushFileBuffers(csv_file);pCloseHandle(csv_file);csv_file=0;}
    if(window)pDestroyWindow(window);pExitProcess((Dword)exit_code);
}
