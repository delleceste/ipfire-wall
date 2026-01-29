#include <QTableWidget>
#include <ipfire_structs.h>

class IQFTable : public QTableWidget
{
	Q_OBJECT
			
	public:
		
	IQFTable(QWidget *parent);
	~IQFTable();
	
	void setRule(ipfire_rule* r) { rule = r; }
	
	protected:
		
	private:
		ipfire_rule *rule;
};






















