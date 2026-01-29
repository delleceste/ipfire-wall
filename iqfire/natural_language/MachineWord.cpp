#include "includes/MachineWord.h"

MachineWord::MachineWord(QString s) : QString(s)
{
  d_error = false;
  d_errMsg = "Machine Word without errors";
}

