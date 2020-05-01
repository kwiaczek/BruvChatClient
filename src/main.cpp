#include "chatwindow.h"
#include <QApplication>
#include <QDir>
#include <sodium.h>
#include <iostream>
#include "user.h"
#include "utils.h"
#include "crypto.h"
#include "message.h"
#include "loginwindow.h"
#include "chatwindow.h"
#include <QDialog>
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    //initalize sodium
    if(sodium_init() < 0)
    {
        std::cerr << "Could not initalize sodium!" << std::endl;
        return -1;
    }
    //check wheater aes256gcm is supported
    if(crypto_aead_aes256gcm_is_available() == 0)
    {
        std::cerr << "AES GCM NOT SUPPORTED!" << std::endl;
        return -1;
    }
    //check if users dir exists
    if(!QDir("users/").exists())
    {
        QDir().mkdir("users/");
    }

    std::shared_ptr<User> user = std::make_shared<User>();
    std::shared_ptr<QWebSocket> websocket = std::make_shared<QWebSocket>();


    LoginWindow loginWindow(user, websocket);
    if( loginWindow.exec() != QDialog::Accepted)
    {
        return -1;
    }
    ChatWindow chatwindow(user,websocket);
    chatwindow.show();

    return app.exec();
}
