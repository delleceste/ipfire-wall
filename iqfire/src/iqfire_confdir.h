#ifndef IQFIRE_CONFDIR_H
#define IQFIRE_CONFDIR_H

class IQFireConfdir
{
	public:
		IQFireConfdir();
		int check() { return code; }
		
	private:
		void notifyConfigCheck(int code);
		int code;
};

#endif
