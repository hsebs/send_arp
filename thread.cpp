#include "thread.h"

Thread::Thread(QObject *parent):QThread(parent)
{

}

void Thread::run()
{
    if(routine)
        routine();
}

 void Thread::setRoutine(void (*routine)())
 {
     this->routine=routine;
 }
