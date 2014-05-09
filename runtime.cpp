#include "runtime.h"

RunTime::RunTime(QObject *parent) :
    QObject(parent)
{

}

void RunTime::start()
{
    Wifipcap *cap = new Wifipcap("wlan0");
    cap->Run(this);
}
