#ifndef IQF_MESSAGE_PROXY_H
#define IQF_MESSAGE_PROXY_H

#include <QString>

class IQFTextBrowser;

class IQFMessageProxy
{
	public:
	
		static IQFMessageProxy* msgproxy();
		QString getInfo(QString key);
		QString getHelp(QString key);
		QString getMan(QString key);
		QString insertHelpIntoHtmlHeader(QString s);
		QString insertInfoIntoHtmlHeader(QString s);
		
		
		void setInfoPath(QString p) { _infopath = p; }
		void setHelpPath(QString p) { _helppath = p; }
		void setManPath(QString p) { _manpath = p; }
		void setExtension(QString ext = ".html") { _extension = ext; }
		
		QString helpPaht() { return _helppath; }
		QString infoPath() { return _infopath; }
		QString manPath() { return _manpath; }
		QString extension() { return _extension; }
	
	private: /* Singleton: the constructor is private */
		
		IQFMessageProxy();
		~IQFMessageProxy();
		
		static IQFMessageProxy* _instance;
		
		QString _infopath, _helppath, _manpath, _extension;
		QString opened_info_filename, opened_help_filename, opened_man_filename;
		QString current_info;
		QString current_help;
		QString current_man;
		

};

#endif


