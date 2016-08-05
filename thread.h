#ifndef THREAD_H
#define THREAD_H

#include<QThread>

class Thread : public QThread
{
    Q_OBJECT
private:
    void (*routine)();
    void run();
public:
    explicit Thread(QObject *parent=0);
    void setRoutine(void (*routine)());
signals:

public slots:
};

#endif // THREAD_H
