#ifndef NATURAL_MESSAGE_EVENTS_H
#define NATURAL_MESSAGE_EVENTS_H

#include <QEvent>
#include <QString>

#define OKMESSAGEEVENT (QEvent::Type) 4642
#define WARNMESSAGEEVENT (QEvent::Type) 4643
#define ERRMESSAGEEVENT (QEvent::Type) 4644

class MessageEvent : public QEvent
{
  public:
    MessageEvent(QString& msg, QEvent::Type type) : QEvent(type) { d_msg = msg; }
    QString message() { return d_msg; }
  
  private:
    QString d_msg;
};

class ErrorMessageEvent : public MessageEvent
{
  public:
   ErrorMessageEvent(QString &msg) : MessageEvent(msg, ERRMESSAGEEVENT) {};
};

class WarningMessageEvent : public MessageEvent
{
  public:
   WarningMessageEvent(QString &msg) : MessageEvent(msg, WARNMESSAGEEVENT) {};
};

class OkMessageEvent : public MessageEvent
{
  public:
    OkMessageEvent(QString &msg) : MessageEvent(msg, OKMESSAGEEVENT) {};
};

#endif
