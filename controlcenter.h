#ifndef CONTROLCENTER_H
#define CONTROLCENTER_H

#include <QMainWindow>
#include <QStringListModel>
namespace Ui {
class ControlCenter;
}

class ControlCenter : public QMainWindow
{
    Q_OBJECT
    QStringListModel model;
    QStringList list;
    QMap<QString,int> map;
    int counter;
public:
    explicit ControlCenter(QWidget *parent = 0);
    ~ControlCenter();

private:
    Ui::ControlCenter *ui;
private slots:
    void addText(QString txt);
    void updateList();
};

#endif // CONTROLCENTER_H
