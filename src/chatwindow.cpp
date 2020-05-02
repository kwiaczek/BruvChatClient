#include "chatwindow.h"
#include "./ui_chatwindow.h"
#include <string>
#include <QInputDialog>
#include <QJsonObject>
#include <QMessageBox>

ChatWindow::ChatWindow(std::shared_ptr<User> user, std::shared_ptr<QWebSocket> websocket,QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ChatWindow)
{
    ui->setupUi(this);
    m_websocket = websocket;
    m_user = user;
    m_websocket->disconnect();

    ui->welcome_message->setText(QString::fromStdString("Witaj " + m_user->username + "(" + std::to_string(m_user->current_device->deviceid) + ")!"));

    setWindowTitle(QString::fromStdString("BruvChatClient - " + m_user->username));

    connect(ui->add_correspondent, SIGNAL(released()), this, SLOT(addCorrespondent()));
    connect(m_websocket.get(), &QWebSocket::textMessageReceived, this, &ChatWindow::handleResponses);

    QJsonObject fetch_messages_msg{
        {"type", "fetch_messages"}
    };
    m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(fetch_messages_msg).toJson().toStdString()));
}

ChatWindow::~ChatWindow()
{
    save_to_encrypted_file(("users/"+m_user->username), m_user->password, QJsonDocument(m_user->toJson(USER_PRIVATE)).toJson().toStdString());
    delete ui;
}

void ChatWindow::addCorrespondent()
{
    bool ok;
    QString username = QInputDialog::getText(this, tr("Dodaj użytkownika"), tr("Nazwa użytkownika: "), QLineEdit::Normal, nullptr, &ok);

    QJsonObject add_correspondent_json;
    add_correspondent_json.insert("type", "add_correspondent");
    QJsonObject data;
    data.insert("from_userid", m_user->userid);
    data.insert("from_username", QString::fromStdString(m_user->username));
    data.insert("to_username", username);
    data.insert("type", "add_correspondent");
    add_correspondent_json.insert("data" , data);

    if( ok && !username.isEmpty())
        m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(add_correspondent_json).toJson().toStdString()));

}

void ChatWindow::handleResponses(QString msg)
{
    QJsonDocument server_response = QJsonDocument::fromJson(msg.toUtf8());
    if(server_response["type"] == "fetch_messages")
    {
        QJsonArray data = server_response["data"].toArray();
        for(int i =0; i < data.size(); i++)
        {
            handleResponses(QString::fromStdString(QJsonDocument(data[i].toObject()).toJson().toStdString()));
        }
    }
    else if(server_response["type"] == "add_correspondent")
    {
        QMessageBox::StandardButton reply = QMessageBox::question(this, "Otrzymałeś zaproszenie!", QString::fromStdString("Czy chcesz dodać użytkownika " + server_response["from_username"].toString().toStdString() + " do znajomych?" ), QMessageBox::Yes|QMessageBox::No);
        if(reply == QMessageBox::Yes)
        {
            QJsonObject accept_message{
                {"type", "add_correspondent_accepted"},
                {"from_userid", server_response["from_userid"].toInt()},
                {"to_userid", server_response["to_userid"].toInt()}
            };
            m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(accept_message).toJson().toStdString()));
        }
    }
}

