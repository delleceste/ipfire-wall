#include <ipfire_structs.h>
#include <QStringList>


extern "C"
{
	void init_rule(ipfire_rule* rule);
	void remove_exclmark(char* addr);
	int get_line(char * dest);
	int is_cidr(const char* addr);
	int fill_not_ip_interval(const char* addr, ipfire_rule* r, int direction);
	int fill_ip_interval(const char* addr, ipfire_rule* r, int direction);
	int cidr_to_interval(char* addr);
	int is_interval(const char* line);
	int fill_not_ip(const char* naddr, ipfire_rule* r, int direction);
	int fill_plain_address(const char* naddr, ipfire_rule* r, 
			       int direction);
	int fill_not_port(const char* port, ipfire_rule* r, int direction);
	int check_port_interval(int p1, int p2);
	int check_port_interval(int p1, int p2);
	int check_port_interval(int p1, int p2);
	int fill_port_interval(const char* port, ipfire_rule* r, int direction);
	int fill_not_port_interval(const char* port, ipfire_rule* r, int direction);
	int fill_plain_port(const char* port, ipfire_rule* r, int direction);
	
}

class RuleBuilder
{
	public:
		RuleBuilder();
		RuleBuilder(ipfire_rule initialized_rule);
		
		~RuleBuilder();
		
		ipfire_rule* Rule() { return rule; }
		
		void setPolicy(QString policy);
		void setPolicy(int policy);
		void setInDevname(QString devname);
		void setOutDevname(QString devname);
		void setSip(QString s);
		void setDip(QString s);
		void setSport(QString s);
		void setDport(QString s);
		void setOwner(int uid);
		void setOwner(QString username);
		void setNotify(QString notify);
		/** TCP, UDP, ICMP */ 
		void setProtocol(QString p);
		void setDirection(QString d);
		void setDirection(int d);
		/** This accepts NAT, SNAT, MASQUERADE or MASQ */
		void setNatType(QString type);
		/** flags must be 
		 * SYN on ACK off URG off [...]
		 * as built by rule_stringifier and separated
		 * by spaces 
		 */
		void setFlags(QString flags);
		/** state can be 
		 * YES
		 * or
		 * NO
		*/
		void setState(QString state);
		
		/** ftp can be 
		 * YES
		 * or
		 * NO
		 */
		void setFTP(QString ftp);
		void setName(QString name);
		void setNewIP(QString ip);
		void setNewPort(QString port);
		
		void setMssOption(int opt);
		void setMssValue(unsigned short value);
		void setOptions(QString s);
                void setFtpSupport(QString s);
		
		void init();
		
		bool ruleValid() { return _ruleValid; }
		QStringList failureReasons() { return _failureReasons; }
		QString failuresHtmlRepresentation();
		
	private:
		ipfire_rule *rule;
		
		/* A simplified version of 
		 * int get_in_address(char* addr, ipfire_rule* r, int direction, int hook)
		 * in interface_functions.c of ipfi package.
		 * direction can be SOURCE or DEST.
		 */
		int ip_helper(char* addr, int direction);
		
		/* a version of get_in_port.
		 * get_in_port could have been used directly, but 
		 * reporting it can help the reader to know what we
		 * are doing.
		 * The called functions rely on common.c ones.
		 */
		int port_helper(char *port, int direction);
		
		/* Taken from the ipfi lib, but without the fgets() obviously */
		int get_line(char *line);
		bool _ruleValid;
		QStringList _failureReasons;
		bool isAny(QString &s);
		bool fillIPList(QString ips, ipfire_rule* prule, int direction, bool different);
		bool fillPortList(QString ips, ipfire_rule* prule, int direction, bool different);
};











