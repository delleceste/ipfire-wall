#include "naturalProgressBar.h"

NaturalProgressBar::NaturalProgressBar(QWidget *parent) : QProgressBar(parent)
{
    d_text = QProgressBar::text();
}




