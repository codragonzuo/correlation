#include "Correlation.h"
#include <iostream>

using namespace std;

Correlation corre;

int main()
{
    cout << "Hello world!" << endl;
    Event event;
    //cout << xmltest() << endl;
    corre.DoCorrelation(event);

    return 0;
}
