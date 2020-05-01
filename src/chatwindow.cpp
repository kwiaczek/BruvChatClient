#include "chatwindow.h"
#include "./ui_chatwindow.h"

ChatWindow::ChatWindow(std::shared_ptr<User> user, std::shared_ptr<QWebSocket> websocket,QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ChatWindow)
{
    ui->setupUi(this);
    m_websocket = websocket;
    m_user = user;


    std::cout << QJsonDocument(m_user->toJson(USER_PRIVATE)).toJson().toStdString() << std::endl;
}

ChatWindow::~ChatWindow()
{
    delete ui;
}

