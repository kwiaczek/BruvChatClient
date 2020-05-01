#include "chatwindow.h"
#include <QApplication>
#include <sodium.h>
#include <iostream>
#include "user.h"
#include "utils.h"
#include "crypto.h"
#include "message.h"
#include "loginwindow.h"
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    //initalize sodium
    if(sodium_init() < 0)
    {
        std::cerr << "Could not initalize sodium!" << std::endl;
        return -1;
    }

    if(crypto_aead_aes256gcm_is_available() == 0)
    {
        std::cerr << "AES GCM NOT SUPPORTED!" << std::endl;
        return -1;
    }

    std::shared_ptr<User> user = std::make_shared<User>();
    std::shared_ptr<QWebSocket> websocket = std::make_shared<QWebSocket>();


    LoginWindow loginWindow(user, websocket);
    loginWindow.show();

    return app.exec();
}
