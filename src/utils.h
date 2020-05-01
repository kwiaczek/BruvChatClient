#ifndef UTILS_H
#define UTILS_H
#include <vector>
#include <QByteArray>
#include <sodium.h>
#include <iostream>
#include <QJsonObject>
#include <QFile>
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

static void save_to_encrypted_file(const std::string & path, const std::string & password, const std::string & plaintext)
{
    std::vector<unsigned char> plaintext_bytes(plaintext.begin(), plaintext.end());
    //derive key
    std::vector<unsigned char> key;
    key.resize(crypto_generichash_BYTES);
    crypto_generichash(key.data(), key.size(), (const unsigned char *)password.data(), password.size(), NULL, 0);
    //encrypt
    std::vector<unsigned char> header(crypto_secretstream_xchacha20poly1305_HEADERBYTES);
    std::vector<unsigned char> ciphertext(plaintext_bytes.size() + crypto_secretstream_xchacha20poly1305_ABYTES);

    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_push(&state, header.data(), key.data());
    crypto_secretstream_xchacha20poly1305_push(&state, ciphertext.data(), NULL, plaintext_bytes.data(), plaintext_bytes.size(), NULL,0,crypto_secretstream_xchacha20poly1305_TAG_FINAL);


    //save to file
    QFile file(path.c_str());
    if(!file.open(QIODevice::Truncate | QIODevice::ReadWrite	))
    {
        return;
    }

    file.write(QByteArray((const char * ) header.data(), header.size()).toBase64());
    file.write(QByteArray((const char * ) ciphertext.data(), ciphertext.size()).toBase64());
}

static std::string read_encrypted_file(const std::string & path, const std::string & password)
{
    //derive key
    std::vector<unsigned char> key;
    key.resize(crypto_generichash_BYTES);
    crypto_generichash(key.data(), key.size(), (const unsigned char *)password.data(), password.size(), NULL, 0);
    //read file
    QFile file(path.c_str());
    if(!file.open(QIODevice::ReadOnly))
    {
        return "";
    }
    QByteArray file_bytes = QByteArray(QByteArray::fromBase64(file.readAll()));

    std::vector<unsigned char> header(file_bytes.begin(), file_bytes.begin() + crypto_secretstream_xchacha20poly1305_HEADERBYTES);
    std::vector<unsigned char> ciphertext(file_bytes.begin() + crypto_secretstream_xchacha20poly1305_HEADERBYTES , file_bytes.end());
    //decrypt
    std::vector<unsigned char> plaintext(ciphertext.size() - crypto_secretstream_xchacha20poly1305_ABYTES);
    crypto_secretstream_xchacha20poly1305_state state;



    if(crypto_secretstream_xchacha20poly1305_init_pull(&state, header.data(), key.data()) != 0)
    {
        std::cerr << "Corrupted header" << std::endl;
        return "";
    }

    unsigned char tag;
    if(crypto_secretstream_xchacha20poly1305_pull(&state, plaintext.data(), NULL, &tag, ciphertext.data(), ciphertext.size(), NULL, 0) != 0)
    {
        std::cerr << "Corrupted ciphertext" << std::endl;
        return "";
    }

    return  std::string(plaintext.begin(), plaintext.end());
}

#endif // UTILS_H
