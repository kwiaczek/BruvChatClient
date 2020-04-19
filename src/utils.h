#ifndef UTILS_H
#define UTILS_H
#include <vector>
#include <QByteArray>
#include <iostream>
#include <QJsonObject>
#include <QJsonDocument>

static QString bytesToBase64qstring(const std::vector<unsigned char> & x)
{
    return QString::fromStdString(QByteArray((const char * )x.data(), x.size()).toBase64().toStdString());
}

static std::string bytesToBase64string(const std::vector<unsigned char> & x)
{
    return QByteArray((const char * )x.data(), x.size()).toBase64().toStdString();
}

static std::vector<unsigned char> base64QStringToBytes(const QString & x)
{
    QByteArray tmp = QByteArray::fromBase64(x.toStdString().c_str());
    std::vector<unsigned char> tmp2(tmp.begin(), tmp.end());
    return tmp2;
}

static void printVecBase64(const std::vector<unsigned char> & x)
{
    std::cout << bytesToBase64string(x) << std::endl;
}

static std::string jsonObjToString(const QJsonObject & obj)
{
    return QJsonDocument(obj).toJson().toStdString();
}

static QJsonDocument jsonStringToJsonDocument(const std::string & x)
{
    return QJsonDocument::fromJson(x.c_str());
}

#endif // UTILS_H
