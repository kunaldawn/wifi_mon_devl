#-------------------------------------------------
#
# Project created by QtCreator 2014-05-09T09:35:11
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = wifi_mon
TEMPLATE = app


SOURCES += main.cpp\
        controlcenter.cpp \
        cpack.cpp \
        TimeVal.cpp \
        wifipcap.cpp \
    runtime.cpp


HEADERS  += controlcenter.h \
            arp.h \
            cpack.h \
            ether.h \
            ethertype.h \
            extract.h \
            icmp.h \
            ieee802_11_radio.h \
            ip.h \
            ip6.h \
            ipproto.h \
            llc.h \
            oui.h \
            prism.h \
            radiotap.h \
            tcp.h \
            TimeVal.h \
            types.h \
            udp.h \
            wifipcap.h \
    runtime.h

FORMS    += controlcenter.ui

LIBS += -lpcap

RESOURCES +=
