#ifndef IQFPOLICY_H
#define IQFPOLICY_H

#include <QObject>
#include <QVector>
#include <QString>
#include <QList>
#include <list.h> 
#include <ipfire_structs.h>  
#include <common.h>

class Log;

/* This is a singleton: at every time during the execution, there
 * must be only one instance of this object (only one ruleset,
 * only one policy at a given moment.
 */
class Policy : public QObject
{
	Q_OBJECT
	public:
		/** Returns the single instance of this class.
		 * The class contains and manages the ruleset of
		 * the user that executes iQfirewall.
		 * The rules of the administrator loaded into the 
		 * kernel are not stored nor managed in any form
		 * inside the Policy class.
		 * The public methods setDenialRules(), setAcceptRules()
		 * and setTranslationRules() check the owner before adding
		 * the rule in the list.
		 */
		static Policy *instance();
		
		QString permission_filename, blacklist_filename,
		translation_filename, blacksites_filename;
		
		QVector<ipfire_rule > DenialRules() { return denial_rules; }
		QVector<ipfire_rule > PermissionRules() { return accept_rules; }
		QVector<ipfire_rule > TranslationRules() { return translation_rules; }
		
		int DefaultPolicy() { return default_policy; }
		
		/** Calls SendRulesToKernel for each vector of rules */
		int SendAllRulesToKernel();
		
		/** Reads the ruleset from the kernel and places in the QVector 
		 * the references to the rules
		 * Returns the number of rules got or a negative value if an error
		 * occurs.
		 * Fills in adm_xxx_rules with the rules belonging to root.
		*/
		int GetKernelRules(QVector<ipfire_rule > &v_den,
				   QVector<ipfire_rule > &v_acc,
				   QVector<ipfire_rule > &v_tr);
				   
		int GetCurrentUserKernelRules(QVector<ipfire_rule > &v_den,
				   QVector<ipfire_rule > &v_acc,
				   QVector<ipfire_rule > &v_tr);
		
		bool AllocOk() { return allocation_succeeded; }
		
		/** Sets the denial rules, checking that the owner of 
		 * the passed rule is equal to getuid()
		 */
		int setDenialRules(QVector <ipfire_rule> dr);
		/** Sets the permission rules, checking that the owner of 
		 * the passed rule is equal to getuid()
		 */
		int setAcceptRules(QVector <ipfire_rule> ar);
		/** Sets the translation rules, checking that the owner of 
		 * the passed rule is equal to getuid()
		 */
		int setTranslationRules(QVector <ipfire_rule> tr);
		
		void updateDenialRules();
		void updateAcceptRules();
		void updateTranslationRules();
		
		QList<unsigned int> rulesNumbers();

		/** This appends the new rule to the appropriate list
		 * and updates the kernel rules.
		 */
		int appendRule(ipfire_rule& newrule);
		
		void notifyRulesChanged() { emit rulesChanged(); }
		
		/** gets the permission rule with position pos and owner owner.
		 *  It really returns a reference to a rule, since each possible rule
		 * returned by this method lives in this class, inside the `accept_rules'
		 * or `admin_accept_rules' vectors.
		 */
		ipfire_rule& permissionRuleByPosition(int pos, bool admin);
		
		
	signals:
		/** The following signals that the permission/denial rules have been updated */
		void rulesChanged();
		void saveProgressChanged(int);
		void saveProgressMaximum(int);
		
		
	protected slots:
		/** Updates all rules in the kernel.
		 * First flushes the current rules, then writes 
		 * the new ones.
		 * Verifies the UID before updating the rules, 
		 * updating just the user's rules.
		*/
		void updateAllKernelRules(QVector<ipfire_rule *> all_rules);	
		
		void saveRules();
		
		
	private:
		
		/* Reads the rule from the file and allocates it.
		 * At the end, when each vector is formed, it updates
		 * the position of the rule basing on the position inside
		 * the vector.
		 */
		int AllocateRules();
		void ReloadRules();
		void GetFileNames();
		int DeleteRule(int position);
		int AddRUle(int position);
		void updateRules(int policy);
		
		
		int SendRulesToKernel(QVector<ipfire_rule > rules);
		
		QVector<ipfire_rule > parse_rulefile_and_alloc_ruleset
			(FILE* fp, int whichfile);
		
		ipfire_rule *ToLowLevelRulePointer(QVector<ipfire_rule *> in);
		
		/* The three vectors will store and manage 
		 * ONLY the RULES OWNED BY the USER executing
		 * iqfire.
		 * That is, only the rules with owner == getuid()
		 * will be stored.
		 */
		QVector<ipfire_rule> denial_rules;
		QVector<ipfire_rule> accept_rules;
		QVector<ipfire_rule> translation_rules;
		
		/* the following three vectors store the administrator rules.
		 * They might be equal to the three above if the user launching iqfire
		 * is root. The vectors are filled by GetKernelRules above 
		 */
		QVector<ipfire_rule> adm_denial_rules;
		QVector<ipfire_rule> adm_accept_rules;
		QVector<ipfire_rule> adm_translation_rules;
		
		int default_policy;
		bool allocation_succeeded;
		
		Policy();
		~Policy();
		
		static Policy* _instance;
		Log* log;
		/* a rule filled with zeroes, used if needed to return a null rule */
		ipfire_rule d_nullRule;
};


#endif




