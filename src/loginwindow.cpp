#include "loginwindow.h"
#include "ui_loginwindow.h"
#include <QMessageBox>
#include <iostream>
#include <QFile>

LoginWindow::LoginWindow(std::shared_ptr<User> user, std::shared_ptr<QWebSocket> websocket, QWidget *parent):
    QDialog(parent),
    ui(new Ui::LoginWindow)
{
    ui->setupUi(this);
    m_user = user;
    m_websocket = websocket;

    connect(m_websocket.get(),&QWebSocket::connected, this, & LoginWindow::onConnected);
    connect(m_websocket.get(), QOverload<const QList<QSslError>&>::of(&QWebSocket::sslErrors),
                        this, &LoginWindow::onSslErrors);
    m_websocket->open(QUrl("wss://localhost:9300"));
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

    QString username = ui->sign_in_username->text();
    m_user->username = username.toStdString();
    QString password = ui->sign_in_password->text();
    m_user->password = password.toStdString();

    //check if there is local copy of data
    if(QFile(("users/"+username.toStdString()).c_str()).exists())
    {
        std::string user_data_decrypted = read_encrypted_file(("users/"+username.toStdString()), password.toStdString());
        if(user_data_decrypted != "")
        {
            m_user->parseJson(QJsonDocument::fromJson(user_data_decrypted.c_str()));

            QJsonObject login_with_data_msg{
                {"type", "loginwithdata"},
                {"data", QJsonObject{
                    {"username", username},
                    {"password", password},
                    {"userid", m_user->userid},
                    {"deviceid", m_user->current_device->deviceid}
                }}
            };
            m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(login_with_data_msg).toJson().toStdString()));
        }
        else
        {
            std::cout << "Error while reading the file!" << std::endl;
        }
    }
    else
    {
        m_user->current_device = new Device();

        QJsonObject login_with_no_data_msg{
            {"type", "loginwithnodata"},
            {"data", QJsonObject{
                {"username", username},
                {"password", password},
                {"data", m_user->toJson(USER_PUBLIC)}
            }}
        };
        m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(login_with_no_data_msg).toJson().toStdString()));
    }
}

void LoginWindow::handleBruvLoginMsg(QString msg)
{
    m_websocket->disconnect();
    QJsonDocument server_response = QJsonDocument::fromJson(msg.toUtf8());


    if(server_response["type"] == "loginwithnodata_accepted")
    {
        m_user->userid = server_response["userid"].toInt();
        m_user->current_device->deviceid = server_response["deviceid"].toInt();

        this->accept();
    }
    else if(server_response["type"] == "loginwithdata_accepted")
    {
        save_to_encrypted_file(("users/"+m_user->username), m_user->password, QJsonDocument(m_user->toJson(USER_PRIVATE)).toJson().toStdString());

        this->accept();
    }
    else if(server_response["type"] == "loginwithnodata_rejected" || server_response["type"] == "loginwithdata_rejected")
    {
        QMessageBox::critical(this, "Logowanie", "Logowanie zakończyło się niepowodzeniem!");
    }
}

void LoginWindow::handleBruvRegisterMsg(QString msg)
{
    m_websocket->disconnect();

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

void LoginWindow::onSslErrors(const QList<QSslError> &errors)
{
    //ALLOW SELF-SIGNED CERTIFICATE
    m_websocket->ignoreSslErrors();
}
