#include "chatwindow.h"
#include "./ui_chatwindow.h"
#include <string>
#include <QInputDialog>
#include <QJsonObject>
#include <QListWidget>
#include <QMessageBox>

ChatWindow::ChatWindow(std::shared_ptr<User> user, std::shared_ptr<QWebSocket> websocket,QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ChatWindow)
{
    ui->setupUi(this);
    //disconnecto all SIGNALS from websocket
    m_websocket->disconnect();

    //pass websocket and user class used in loginwindow
    m_websocket = websocket;
    m_user = user;

    //ui
    ui->welcome_message->setText(QString::fromStdString("Witaj " + m_user->username + "(" + std::to_string(m_user->current_device->deviceid) + ")!"));
    setWindowTitle(QString::fromStdString("BruvChatClient - " + m_user->username));

    //message handler
    connect(m_websocket.get(), &QWebSocket::textMessageReceived, this, &ChatWindow::handleResponses);
    //button add correspondent
    connect(ui->add_correspondent, SIGNAL(released()), this, SLOT(addCorrespondent()));
    //correspondent list
    connect(ui->correspondents_list, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(selectCorrespondent(QListWidgetItem*)));
    //update correspondents and messages
    requestUpdate();
    //nullptr means no correspondent has been selected
    last_selected = nullptr;
}

ChatWindow::~ChatWindow()
{
    save_to_encrypted_file(("users/"+m_user->username), m_user->password, QJsonDocument(m_user->toJson(USER_PRIVATE)).toJson().toStdString());
    delete ui;
}

void ChatWindow::createCorresponentList()
{
    for(auto it = m_user->current_device->correspondents.begin(); it != m_user->current_device->correspondents.end();it ++)
    {
        QListWidgetItem * new_item = new QListWidgetItem();
        new_item->setText(QString::fromStdString(it->second->username));
        corresponend_list_items[new_item] = it->first;
        ui->correspondents_list->addItem(new_item);
    }
}

void ChatWindow::selectCorrespondent(QListWidgetItem *item)
{
    last_selected = item;
    std::cout << m_user->current_device->correspondents[corresponend_list_items[last_selected]]->username << std::endl;
}

void ChatWindow::handleResponses(QString msg)
{
    QJsonDocument server_response = QJsonDocument::fromJson(msg.toUtf8());

    if(server_response["type"] == "outdated")
    {
        requestUpdate();
    }
    else if(server_response["type"] == "add_correspondent_request")
    {
        QMessageBox::StandardButton reply = QMessageBox::question(this, "Otrzymałeś zaproszenie!", QString::fromStdString("Czy chcesz dodać użytkownika " + server_response["from_username"].toString().toStdString() + " do znajomych?" ), QMessageBox::Yes|QMessageBox::No);
        if(reply == QMessageBox::Yes)
        {
            QJsonObject accept_message{
                {"type", "accept_correspondent_request"},
                {"from_userid", server_response["from_userid"].toInt()},
                {"to_userid", server_response["to_userid"].toInt()}
            };
            m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(accept_message).toJson().toStdString()));
            requestUpdate();
        }
    }
    else if(server_response["type"] == "request_update")
    {
        m_user->current_device->parseJsonCorrespondents(server_response["correspondents"].toArray());
        QJsonArray messages = server_response["messages"].toArray();
        for(int i= 0; i < messages.size(); i++)
        {
            handleResponses(QString::fromStdString(QJsonDocument(messages[i].toObject()).toJson().toStdString()));
        }
        createCorresponentList();

        std::cout << QJsonDocument(m_user->toJson(USER_PRIVATE)).toJson().toStdString() << std::endl;
    }
}

void ChatWindow::requestUpdate()
{
    QJsonObject request_update_json;
    request_update_json.insert("type", "request_update");
    m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(request_update_json).toJson().toStdString()));
}

void ChatWindow::addCorrespondent()
{
    bool ok;
    QString correspondent_username = QInputDialog::getText(this, tr("Dodaj użytkownika"), tr("Nazwa użytkownika: "), QLineEdit::Normal, nullptr, &ok);

    QJsonObject add_correspondent_json;
    add_correspondent_json.insert("type", "add_correspondent_request");
    QJsonObject data;
    data.insert("from_userid", m_user->userid);
    data.insert("from_username", QString::fromStdString(m_user->username));
    data.insert("to_username", correspondent_username);
    data.insert("type", "add_correspondent_request");
    add_correspondent_json.insert("data" , data);

    if( ok && !correspondent_username.isEmpty())
    {
        m_websocket->sendTextMessage(QString::fromStdString(QJsonDocument(add_correspondent_json).toJson().toStdString()));
    }
}

