#ifndef RUNTIME_H
#define RUNTIME_H

#include <QObject>
#include "wifipcap.h"

class RunTime : public QObject, public WifipcapCallbacks
{
    Q_OBJECT
public:
    explicit RunTime(QObject *parent = 0);
    virtual void Handle80211MgmtBeacon(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body)   {
        if(body->ssid.length > 1)
         emit(addText(body->ssid.ssid));
    }
    virtual void HandleRadiotap(const WifiPacket &p, struct radiotap_hdr *hdr, const u_char *rest, size_t len){
        //emit(addText(QString::number(hdr->signal_dbm)));
    }

signals:
    void addText(QString txt);
public slots:
    void start();

};

#endif // RUNTIME_H
