#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../source/sender_core.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static unsigned sent,fail_at;static CanFrame frames[1024];
static int transmit(void *c,const CanFrame *f){(void)c;CHECK(sent<1024);frames[sent++]=*f;return fail_at && sent==fail_at?-1:0;}
int main(void){
    CanFrame f;CanSchedule s;CanStep steps[MAX_STEPS];uint32_t n;unsigned count,line,i;char huge[20000];
    CHECK(can_frame("0x5c1","28 00 00 60",0,&f) && f.id==0x5c1 && f.size==4 && f.data[3]==0x60);
    CHECK(can_frame("7FF","0011223344556677",0,&f) && f.size==8);
    CHECK(can_frame("000","",0,&f) && f.size==0);
    CHECK(can_frame("1fffffff","01",1,&f));CHECK(!can_frame("20000000","01",1,&f));
    CHECK(!can_frame("800","01",0,&f));CHECK(!can_frame("-1","01",0,&f));CHECK(!can_frame("","01",0,&f));
    CHECK(!can_frame("100000000","00",1,&f));CHECK(!can_frame("7FF!","00",0,&f));
    CHECK(!can_frame("7FF","0",0,&f));CHECK(!can_frame("7FF","1 2",0,&f));
    CHECK(!can_frame("7FF","00 11 22 33 44 55 66 77 88",0,&f));CHECK(!can_frame("7FF","0x12",0,&f));
    CHECK(can_uint(" 60000 ",60000,&n) && n==60000);CHECK(!can_uint("60001",60000,&n));
    CHECK(!can_uint("-100",60000,&n));CHECK(!can_uint("9999999999999999999999",1000000,&n));
    CHECK(can_script(";comment\r\n5C1#28 00 00 60@100\r\n5C1#00 00 00 60@200\n",0,steps,&count,&line) && count==2);
    CHECK(!can_script("5C1#28 00 00 60@100\n5C1#GG@100",0,steps,&count,&line) && line==2 && count==0);
    CHECK(!can_script("5C1#@19",0,steps,&count,&line));CHECK(!can_script("5C1#@60001",0,steps,&count,&line));
    CHECK(!can_script("5C1#00",0,steps,&count,&line));CHECK(!can_script("5C1 00@100",0,steps,&count,&line));
    CHECK(!can_script("; only comment\n",0,steps,&count,&line));CHECK(can_script("5C1#@20",0,steps,&count,&line));
    huge[0]=0;for(i=0;i<MAX_STEPS;i++)strcat(huge,"5C1#@20\n");CHECK(can_script(huge,0,steps,&count,&line) && count==128);
    strcat(huge,"5C1#@20\n");CHECK(!can_script(huge,0,steps,&count,&line) && line==129);
    memset(&s,0,sizeof(s));CHECK(can_frame("5C1","28 00 00 60",0,&s.steps[0].frame));s.steps[0].delay=100;
    sent=0;can_schedule_start(&s,1,3,1000,transmit,0);
    CHECK(can_schedule_tick(&s,999)==0 && sent==0);CHECK(can_schedule_tick(&s,1000)==1 && sent==1);
    CHECK(!can_schedule_tick(&s,1099));CHECK(can_schedule_tick(&s,1100)==1);CHECK(can_schedule_tick(&s,10000)==1 && sent==3 && !s.active && s.completed==3);
    CHECK(!can_schedule_tick(&s,10000));
    sent=0;can_schedule_start(&s,1,0,0xffffffc0u,transmit,0);CHECK(can_schedule_tick(&s,0xffffffc0u)==1);
    CHECK(!can_schedule_tick(&s,35));CHECK(can_schedule_tick(&s,36)==1);CHECK(s.active && sent==2);
    can_schedule_stop(&s);CHECK(!can_schedule_tick(&s,9999) && sent==2);
    sent=0;fail_at=2;can_schedule_start(&s,1,0,0,transmit,0);CHECK(can_schedule_tick(&s,0)==1);CHECK(can_schedule_tick(&s,100)==-1 && !s.active);fail_at=0;
    CHECK(can_script("100#01@20\n101#02@50",0,s.steps,&count,&line));sent=0;can_schedule_start(&s,count,2,0,transmit,0);
    CHECK(can_schedule_tick(&s,0)==1);CHECK(can_schedule_tick(&s,20)==1);CHECK(!can_schedule_tick(&s,69));CHECK(can_schedule_tick(&s,70)==1);CHECK(can_schedule_tick(&s,90)==1 && !s.active && sent==4);
    CHECK(frames[0].id==0x100 && frames[1].id==0x101 && frames[2].id==0x100);
    /* Bounded randomized parser input under ASan/UBSan. */
    for(i=0;i<30000;i++){unsigned j,len=(unsigned)rand()%350;for(j=0;j<len;j++)huge[j]=(char)(1+rand()%126);huge[len]=0;can_script(huge,i&1,steps,&count,&line);can_id(huge,i&1,&n);can_data(huge,&f);}
    puts("PASS HEX boundaries, DLC limits, atomic script validation, 128-step bound, finite/infinite schedules, STOP, TX error, no catch-up, tick wrap, parser fuzz");return 0;
}
