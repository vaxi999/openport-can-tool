#ifndef OPENPORT_SENDER_CORE_H
#define OPENPORT_SENDER_CORE_H
#include <stdint.h>

/* Classic CAN only. IDs and all payload bytes are hexadecimal. */
typedef struct { uint32_t id; unsigned size,extended; uint8_t data[8]; } CanFrame;
typedef struct { CanFrame frame; uint32_t delay; } CanStep;
#define MAX_STEPS 128
typedef int (*CanSend)(void *,const CanFrame *);
typedef struct {
    CanStep steps[MAX_STEPS]; unsigned count,index,active,completed,limit;
    uint32_t due; CanSend send; void *context;
} CanSchedule;
static int can_space(char c) { return c==' ' || c=='\t' || c=='\r' || c=='\n'; }
static int can_hex(char c) {
    if(c>='0' && c<='9')return c-'0';
    if(c>='a' && c<='f')return c-'a'+10;
    if(c>='A' && c<='F')return c-'A'+10;
    return -1;
}
static int can_uint(const char *s,uint32_t maximum,uint32_t *out) {
    uint32_t n=0;unsigned used=0;
    while(can_space(*s))s++;
    while(*s>='0' && *s<='9') { unsigned d=(unsigned)(*s++-'0');if(n>maximum/10 || (n==maximum/10 && d>maximum%10))return 0;n=n*10+d;used++; }
    while(can_space(*s))s++;
    if(!used || *s)return 0;*out=n;return 1;
}
static int can_id(const char *s,unsigned extended,uint32_t *out) {
    uint32_t n=0,maximum=extended?0x1fffffffu:0x7ffu;unsigned used=0;int d;
    while(can_space(*s))s++;
    if(s[0]=='0' && (s[1]=='x' || s[1]=='X'))s+=2;
    while((d=can_hex(*s))>=0) { if(++used>8 || n>(maximum-(unsigned)d)/16u || (unsigned)d>maximum)return 0;n=n*16+(unsigned)d;s++; }
    while(can_space(*s))s++;
    if(!used || *s || n>maximum)return 0;*out=n;return 1;
}
static int can_data(const char *s,CanFrame *f) {
    int high=-1,d;f->size=0;
    while(*s) {
        if(can_space(*s)) { if(high>=0)return 0;s++;continue; }
        d=can_hex(*s++);if(d<0)return 0;
        if(high<0)high=d;
        else { if(f->size==8)return 0;f->data[f->size++]=(uint8_t)((high<<4)|d);high=-1; }
    }
    return high<0; /* Empty payload is valid DLC 0. */
}
static int can_frame(const char *id,const char *data,unsigned extended,CanFrame *f) {
    f->extended=extended?1:0;return can_id(id,extended,&f->id) && can_data(data,f);
}
/* ID#DATA@delay_ms. All lines are parsed before any transmission begins. */
static int can_script(const char *text,unsigned extended,CanStep *out,unsigned *count,unsigned *bad_line) {
    unsigned line=1,n=0;const char *p=text;
    *count=0;*bad_line=0;
    while(*p) {
        char row[160],id[40],data[80],delay[20];unsigned len=0,i,j,k,at;
        while(*p && *p!='\n') { if(len+1>=sizeof(row)){*bad_line=line;return 0;}row[len++]=*p++; }
        if(*p=='\n')p++;row[len]=0;i=0;while(can_space(row[i]))i++;
        if(!row[i] || row[i]==';' || (row[i]=='/' && row[i+1]=='/')){line++;continue;}
        if(n==MAX_STEPS){*bad_line=line;return 0;}
        j=0;while(row[i] && row[i]!='#'){if(j+1>=sizeof(id))goto bad;id[j++]=row[i++];}id[j]=0;
        if(row[i++]!='#')goto bad;
        j=0;while(row[i] && row[i]!='@'){if(j+1>=sizeof(data))goto bad;data[j++]=row[i++];}data[j]=0;
        if(row[i++]!='@')goto bad;
        k=0;at=i;while(row[at]){if(k+1>=sizeof(delay))goto bad;delay[k++]=row[at++];}delay[k]=0;
        if(!can_frame(id,data,extended,&out[n].frame) || !can_uint(delay,60000,&out[n].delay) || out[n].delay<20)goto bad;
        n++;line++;continue;
bad:   *bad_line=line;return 0;
    }
    if(!n){*bad_line=1;return 0;}*count=n;return 1;
}
static void can_schedule_start(CanSchedule *s,unsigned count,unsigned limit,uint32_t now,CanSend send,void *ctx) {
    s->count=count;s->limit=limit;s->index=0;s->completed=0;s->due=now;s->send=send;s->context=ctx;
    s->active=(count>0 && count<=MAX_STEPS);
}
static void can_schedule_stop(CanSchedule *s) { s->active=0; }
static int can_schedule_tick(CanSchedule *s,uint32_t now) {
    CanStep *step;
    if(!s->active || (int32_t)(now-s->due)<0)return 0;
    step=&s->steps[s->index];
    if(s->send(s->context,&step->frame)<0){s->active=0;return -1;}
    s->due=now+step->delay; /* Never emit catch-up bursts after a late poll. */
    if(++s->index==s->count){s->index=0;s->completed++;if(s->limit && s->completed>=s->limit)s->active=0;}
    return 1;
}
#endif
