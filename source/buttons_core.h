#ifndef BUTTONS_CORE_H
#define BUTTONS_CORE_H
#include <stdint.h>
/* Fixed PQ steering UI input. Never exposes arbitrary CAN IDs or payloads. */
typedef int (*ButtonSend)(void *,uint8_t);
typedef struct {uint8_t key;uint16_t duration;} ButtonClick;
typedef struct {
    ButtonSend send;void *context;
    ButtonClick queue[16];unsigned head,count;
    uint8_t active;uint32_t end,next,ready;
    unsigned fault,cancelled;
} Buttons;
static int button_key_allowed(unsigned key){
    return key==0 || key==0x09 || key==0x0a || key==0x22 || key==0x23 || key==0x28 || key==0x29;
}
static int button_due(uint32_t now,uint32_t at){return (int32_t)(now-at)>=0;}
static void buttons_init(Buttons *b,ButtonSend send,void *context,uint32_t now){
    unsigned i;uint8_t *p=(uint8_t *)b;for(i=0;i<sizeof(*b);i++)p[i]=0;
    b->send=send;b->context=context;b->next=now;b->ready=now+200;
}
static int buttons_enqueue(Buttons *b,unsigned key,unsigned duration){
    unsigned index;if(b->fault || !key || !button_key_allowed(key) || duration<200 || duration>2000 || b->count==16)return 0;
    index=(b->head+b->count)%16;b->queue[index].key=(uint8_t)key;b->queue[index].duration=(uint16_t)duration;b->count++;return 1;
}
static int buttons_emit(Buttons *b,uint8_t key){
    if(b->send(b->context,key)){b->fault=1;b->active=0;b->count=0;return 0;}return 1;
}
static void buttons_tick(Buttons *b,uint32_t now){
    if(b->fault)return;
    if(b->active && button_due(now,b->end)){
        b->active=0;b->ready=now+200;b->next=now;
    }
    if(!b->active && b->count && button_due(now,b->ready)){
        ButtonClick *c=&b->queue[b->head];b->active=c->key;b->end=now+c->duration;
        b->head=(b->head+1)%16;b->count--;b->next=now;
    }
    if(button_due(now,b->next)){
        if(!buttons_emit(b,b->active))return;
        b->next=now+100; /* 100 ms normal steering message period; no catch-up bursts. */
    }
}
static void buttons_cancel(Buttons *b,uint32_t now){
    b->active=0;b->count=0;b->cancelled++;b->ready=now+200;b->next=now+100;
    (void)buttons_emit(b,0); /* Release is attempted even after a previous TX failure. */
}
#endif
