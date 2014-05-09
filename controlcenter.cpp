#include "controlcenter.h"
#include "ui_controlcenter.h"
#include "QSystemTrayIcon"
#include "runtime.h"
#include "QThread"
#include "QTimer"

ControlCenter::ControlCenter(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::ControlCenter)
{
    counter =0;
    QTimer *timer = new QTimer();
    ui->setupUi(this);
    QThread *thd = new QThread();
    RunTime *rt = new RunTime();
    rt->moveToThread(thd);
    connect(thd,SIGNAL(started()),rt,SLOT(start()));
    thd->start();
    connect(rt,SIGNAL(addText(QString)),this,SLOT(addText(QString)));
    model.setStringList(list);
    connect(timer,SIGNAL(timeout()),this,SLOT(updateList()));
    timer->start(500);
}

ControlCenter::~ControlCenter()
{
    delete ui;
}

void ControlCenter::addText(QString txt)
{
    if(!txt.isEmpty())
    map.insert(txt,1);

}

void ControlCenter::updateList()
{
    list.clear();
    foreach(QString key, map.keys())
    {
        list.append("SSID : "+key);
    }
    ui->listWidget->clear();
    ui->listWidget->addItems(list);
    counter ++;
    if(counter >= 10)
    {
        map.clear();
        counter = 0;
    }
}

