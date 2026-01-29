#include "euniqueapplication_interface.h"

ItGiacomosIqfireInterface::ItGiacomosIqfireInterface(const QString &service,
	 const QString &path, const QDBusConnection &connection, QObject *parent)
		: QDBusAbstractInterface(service, path, staticInterfaceName(), connection, parent)
{

}

ItGiacomosIqfireInterface::~ItGiacomosIqfireInterface()
{

}

