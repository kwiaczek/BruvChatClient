#include "loginwindow.h"
#include "ui_loginwindow.h"
#include <QMessageBox>

LoginWindow::LoginWindow(std::shared_ptr<User> user, std::shared_ptr<QWebSocket> websocket, QWidget *parent):
    QDialog(parent),
    ui(new Ui::LoginWindow)
{
    ui->setupUi(this);
    m_user = user;
    m_websocket = websocket;

    connect(m_websocket.get(),&QWebSocket::connected, this, & LoginWindow::onConnected);
    m_websocket->open(QUrl("ws://localhost:9300"));
}

LoginWindow::~LoginWindow()
{
    delete ui;
}

void LoginWindow::onConnected()
{
    std::cout << "Connected!" << std::endl;

    connect(ui->sign_in_button, SIGNAL(released()), this, SLOT(bruvLogin()));
    connect(ui->sign_up_button, SIGNAL(released()), this, SLOT(bruvRegister()));
}

void LoginWindow::bruvRegister()
{
    connect(m_websocket.get(), &QWebSocket::textMessageReceived, this, &LoginWindow::handleBruvRegisterMsg);

    QString username = ui->sign_up_username->text();
    QString password = ui->sign_up_password->text();
    QString password2 = ui->sign_up_password2->text();
    if(password != password2)
    {
        return;
    }


    QJsonObject register_msg = {
        {"type" , "signup"},
        {"data", QJsonObject{
             {"username", username},
             {"password", password}
         }}
    };

    m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(register_msg).toJson().toStdString()));
}

void LoginWindow::bruvLogin()
{
    connect(m_websocket.get(), &QWebSocket::textMessageReceived, this, &LoginWindow::handleBruvLoginMsg);

    QString username = ui->sign_up_username->text();
    m_user->username = username.toStdString();
    QString password = ui->sign_up_password->text();

}

void LoginWindow::handleBruvLoginMsg(QString msg)
{
    m_websocket->disconnect();
}

void LoginWindow::handleBruvRegisterMsg(QString msg)
{
    m_websocket->disconnect();
    std::cout << msg.toStdString() << std::endl;

    QJsonDocument server_response = QJsonDocument::fromJson(msg.toUtf8());

    if(server_response["type"] == "signup_accepted")
    {
        QMessageBox::information(this, "Rejestracja", "Rejestracja zakończyła się powodzeniem!");
    }
    else if(server_response["type"] == "signup_rejected")
    {
        QMessageBox::critical(this, "Rejestracja", "Rejestracja zakończyła się niepowodzeniem!");
    }
}
