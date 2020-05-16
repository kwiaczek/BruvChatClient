#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QDialog>
#include <memory>
#include <QtWebSockets/QtWebSockets>
#include "user.h"

namespace Ui {
class LoginWindow;
}

class LoginWindow : public QDialog
{
    Q_OBJECT
    std::shared_ptr<QWebSocket> m_websocket;
    std::shared_ptr<User> m_user;

public:
    explicit LoginWindow(std::shared_ptr<User> user, std::shared_ptr<QWebSocket> websocket, QWidget *parent = nullptr);
    ~LoginWindow();
private slots:
    void onConnected();
    void bruvRegister();
    void bruvLogin();
    void handleBruvLoginMsg(QString msg);
    void handleBruvRegisterMsg(QString msg);
    void onSslErrors(const QList<QSslError> &errors);
private:
    Ui::LoginWindow *ui;
};

#endif // LOGINWINDOW_H
