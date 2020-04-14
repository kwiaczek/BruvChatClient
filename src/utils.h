#ifndef UTILS_H
#define UTILS_H
#include <vector>
#include <QByteArray>
#include <iostream>


static void printVecBase64(const std::vector<unsigned char> & x)
{
    std::cout << QByteArray((const char * )x.data(), x.size()).toBase64().toStdString() << std::endl;
}

#endif // UTILS_H
