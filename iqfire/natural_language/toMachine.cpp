#include <QApplication>
#include "includes/toMachine.h"
#include "includes/MachineWord.h"
#include "includes/grammar.h"
#include "includes/naturalMessageEvents.h"

NaturalTextToMachine::NaturalTextToMachine(NaturalText *nt, QObject *parent, bool strictCheck) 
  : QObject(parent)
{
  d_naturalText = nt;
  d_strictCheck = strictCheck;
  Q_ASSERT(nt != NULL);
  Q_ASSERT(parent != NULL);
  d_dictionary = Dictionary::instance();
  d_machineText = new MachineText();
  if(strictCheck)
    pinfo("Natural text to machine: strict syntax check enabled");
  else
    pinfo("Natural text to machine: strict syntax check disabled");
}

bool NaturalTextToMachine::convertToMachine()
{
  /* get the list of natural sentences */
  QList<NaturalSentence> sentences = d_naturalText->sentences();
  int rulecnt = 0;
  int pos = 0;
  int len = 0;
  int totSentences = sentences.size();
  int sentenceCnt = 0;
  d_conversionFailed = false;
  d_errmsg = "No error";
  QString progressMsg;
  
  foreach(NaturalSentence ns, sentences)
  {
    if(!ns.containsVerb())
      continue;
    sentenceCnt++;
    pos = -1;
    MachineSentence machineSentence;
    QRegExp spacesRe("\\s+");
    
    /* 1. Look for syntax rules first, and apply them */
    Grammar* grammar = Grammar::instance();
    if(grammar->error()) /* check if grammar has errors */
    {
      QString errmsg = QString("Grammar loading failed with error \"<strong>%1</strong>\"").arg(grammar->lastError());
      ErrorMessageEvent *eme = new ErrorMessageEvent(errmsg);
      qApp->postEvent(parent(), eme);
      return false;
    }
    QList<NaturalWord> wordsWithRule = grammar->wordsWithRule();
    
    int machineWordsAdded = 0;
    int matchingKeywordsNumber = 0;
    QString grammarRules;
    
    pok("1. evaluating natural sentence \"%s\" with grammar rules", qstoc(ns));
    qDebug() << wordsWithRule;
    foreach(NaturalWord nw, wordsWithRule)
    {
      pos = 0;
      int matchedLength = 0;
      pinfo("evaluating word with rule \"%s\"", qstoc(nw));
      NaturalWord nwCopy = nw;
      nwCopy.replace("\n", "\\s+");
      nwCopy.replace(spacesRe, "\\s+");
//       nwCopy.prepend("\\b");
//       nwCopy.append("\\b");
      QRegExp nwRe(nwCopy);
      nwRe.setCaseSensitivity(Qt::CaseInsensitive);
      QPair<int, int>delimiters;
      /* see if there are words with a rule in the NaturalSentence */
      while(pos >= 0)
      {
	/* the same word might appear more than one time: look ahead. For instance, if we looked for
	* `destination', it could have more than one rule and might happen twice in a sentence.
	* So we need a while cycle here.
	*/
	pos += matchedLength;
	pos = nwRe.indexIn(ns, pos);
	printf("pos letta da indexIn: %d\n", pos);
	matchedLength = nwRe.matchedLength();
	if(pos >= 0 && !ns.alreadyRead(pos, matchedLength)) /* found */
	{
	  machineWordsAdded = 0;
	  rulecnt = 0;
	  matchingKeywordsNumber++;
	  /* take all the rules associated to the keyword nw */
	  QList<Rule> rules = grammar->rulesForNaturalWord(nw);
	  foreach(Rule rule, rules)
	  {
	    rulecnt++;
	    pstep("applying rule %d/%d to natural word \"%s\" syntax file \"%s\"", rulecnt, rules.size(), qstoc(nwCopy), qstoc(rule.syntaxFile()));
	    if(ns.alreadyRead(pos, matchedLength))
	    {
	      pinfo("skipping other tests over natural sentence \"%s\": portion %d - %d already read", 
		    qstoc(ns), pos, pos + matchedLength);
	      break;
	    }
	    else
	      pinfo("portion %d-%d not already read: looking for \"\e[0;32m%s\e[0m\": pos: %d", pos, pos + matchedLength, qstoc(nw), pos);
	    QList<MachineWord> mwords = rule.applyToSentence(ns, pos);
	    /* mwords.size() == 0 means that the keyword which has a 
	    * syntax rule does not satisfy the rule itself. This can 
	    * be fine in principle, but the NaturalSentence ns must 
	    * satisfy to at least one rule.
	    */
	    machineWordsAdded += mwords.size();
	    for(int i = 0; i < mwords.size(); i++)
	    {
	      delimiters = rule.portionsOfNaturalSentenceRead().at(i);
	      /* word length = delimiters.second - delimiters.first + 1 */
	      if(!ns.alreadyRead(delimiters.first, delimiters.second - delimiters.first + 1))
	      {
		pstep("rule %d/%d ok: added machine word \"\e[1;32m%s\e[0m\" (delim. %d-%d in \"%s\") syntax file \"%s\"", rulecnt, rules.size(), 
		      qstoc(mwords.at(i)), delimiters.first, delimiters.second, qstoc(ns), qstoc(rule.syntaxFile()));
		machineSentence.addWord(mwords.at(i), delimiters.first);
		machineSentence.mapNaturalToMachine(nw, mwords.at(i));
		ns.setPortionRead(delimiters.first, delimiters.second);
	      }
	      else
		pinfo("portion %d-%d already read, so machine word not added", delimiters.first, delimiters.second);
	    }
	    if(machineWordsAdded > 0) /* we found a rule and applied it successfully */
	      break; /* save time, leave the cycle happy */
	  } /* scanned all rules. Now see if at least one was applied */
	  if(machineWordsAdded == 0) /* no rule was satisfied. Bad! */
	  {
	    grammarRules += QString("<ul>Rules for keyword \"<strong>%1</strong>\": %2</ul>\n").arg(nw).arg(grammar->htmlFormattedSuggestionsForRule(nw));
	    if(d_strictCheck)
	    {
	      perr("strict checking: signaling an error");
	      d_conversionFailed = true;
	      QString errmsg = QString("Syntax error in natural sentence <strong>\"%1\"</strong> (sentence %3): %2 ").arg(ns).arg(grammarRules).arg(sentenceCnt);
	      errmsg += QString("<br/><strong>Note</strong>: strict syntax check is enabled: you can disable it in the "
		"<strong>settings</strong> menu, <cite>Natural Language</strong> tab"); 
	      ErrorMessageEvent *eme = new ErrorMessageEvent(errmsg);
	      qApp->postEvent(parent(), eme);
	    }
	  }
	}
	else
	  pwarn("pos: %d, matchedLength %d, alreadyRead: %d", pos, matchedLength, ns.alreadyRead(pos, matchedLength));
      } /* while pos >= 0 */
      
    }/* foreach(NaturalWord nw, wordsWithRule) */
    
    pinfo("matching keywords %d words added %d", matchingKeywordsNumber , machineWordsAdded);
    if(matchingKeywordsNumber > 0 && machineWordsAdded == 0)
    {
      d_conversionFailed = true;
      QString errmsg = QString("Syntax error in natural sentence <strong>\"%1\"</strong> (sentence %3): %2 ").arg(ns).arg(grammarRules).arg(sentenceCnt);
      ErrorMessageEvent *eme = new ErrorMessageEvent(errmsg);
      qApp->postEvent(parent(), eme);
    }
    
    pok("2. evaluating verbs in natural sentence \"%s\"", qstoc(ns));
    /* 2. verbs: they are sorted by length by the dictionary, from the longer to the shortest */
    QList<NaturalWord> verbs = d_dictionary->verbs(); 
    foreach(NaturalWord nw, verbs) /* convert each! */
    {
      NaturalWord nwCopy = nw;
      nwCopy.replace("\n", "\\s+");
      nwCopy.replace(spacesRe, "\\s+");
      nwCopy.prepend("\\b");
      nwCopy.append("\\b");
      QRegExp nwRe(nwCopy);
      nwRe.setCaseSensitivity(Qt::CaseInsensitive);
      pos = ns.indexOf(nwRe, Qt::CaseInsensitive);
      if(pos >= 0 && !ns.alreadyRead(pos, nw.length())) /* found */
      {
	MachineWord machineKey(d_dictionary->verbsMap().key(nw));
	/* since verbs are ordered from the longer expression to the shortest, the 
	 * first match we find is the most specific. For instance if we find 
	 * "having source port" we keep it as a good entry, and do not look ahead,
	 * where we probably would find the shorter entry "port", which is more 
	 * generic.
	 */
	machineSentence.addWord(machineKey, pos);
	machineSentence.mapNaturalToMachine(nw, machineKey);
	/* the portion read is equal to the start pos + the length minus one */
	ns.setPortionRead(pos, pos + nw.length() - 1); /* NOTE: -1 */
      }
    }
    
    pok("3. evaluating remaining words in natural sentence \"%s\"", qstoc(ns));
    /* 3. look for the other parts of the sentence, called names */
    QList<NaturalWord> names = d_dictionary->names();
    foreach(NaturalWord nw, names)
    {
      NaturalWord nwCopy = nw;
      nwCopy.replace("\n", "\\s+");
      nwCopy.replace(spacesRe, "\\s+");
      nwCopy.prepend("\\b");
      nwCopy.append("\\b");
      QRegExp nwRe(nwCopy);
      nwRe.setCaseSensitivity(Qt::CaseInsensitive);
      pos = ns.indexOf(nwRe, Qt::CaseInsensitive);
      if(pos >= 0 &&  !ns.alreadyRead(pos, nw.length())) /* found */
      {
	MachineWord machineKey(d_dictionary->namesMap().key(nw));
	/* see comments above: at the first match abandon search
	 */
	machineSentence.addWord(machineKey, pos);
	machineSentence.mapNaturalToMachine(nw, machineKey);
	    /* the portion read is equal to the start pos + the length minus one */
	ns.setPortionRead(pos, pos + nw.length() - 1);/* NOTE: -1 */
      }
    }
    
    pok("4. finally evaluating other regexps in natural sentence \"%s\"", qstoc(ns));
    /* 4. look for the regular expressions to capture other things */
    QList<QString> rexps = d_dictionary->regularExpressions();
    int cnt  = 0;
    
    foreach(QString re, rexps)
    {
      pos = 0;
      fflush(stdout);
      cnt++;
      len = 0;
      QRegExp regexp(re);
      regexp.setCaseSensitivity(Qt::CaseInsensitive);
      pos = ns.indexOf(regexp, pos);
      while(pos >= 0 && len < ns.length())
      {
	len++;
	QStringList ct = regexp.capturedTexts();
// 	qDebug() << "captured texts " << ct << "da regexp " << re;
	if(ct.size() > 1)
	{
	  MachineWord mw(ct[1]);
	  if(!ns.alreadyRead(pos, regexp.matchedLength()))
	  {
	    machineSentence.addWord(mw, pos);
	    machineSentence.mapNaturalToMachine(mw, d_dictionary->regexpMap().key(re));
	    /* the portion read is equal to the start pos + the length minus one */
	    ns.setPortionRead(pos, pos +  regexp.matchedLength() - 1); /* NOTE: -1 */
	  }
	}
	/* here not -1! Actually, pos here means next position to start looking for */
	pos += (regexp.matchedLength());
	pos = ns.indexOf(regexp, pos);
      }
    } /* foreach regexps */
    
    /* add the sentence to the `machine' text */
    machineSentence.setAssociatedNaturalSentence(ns);
    d_machineText->addSentence(machineSentence);
    
    progressMsg = QString("to machine conversion (%1/%2)").arg(sentenceCnt).arg(totSentences);
    emit progress(sentenceCnt, totSentences, progressMsg);
    
  } /* external foreach (verbs) */
  
  return true;
  
}

