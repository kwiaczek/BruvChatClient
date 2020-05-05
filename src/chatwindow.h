#ifndef CHATWINDOW_H
#define CHATWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QtWebSockets/QtWebSockets>
#include <memory>
#include "user.h"

QT_BEGIN_NAMESPACE
namespace Ui { class ChatWindow; }
QT_END_NAMESPACE

class ChatWindow : public QMainWindow
{
    Q_OBJECT
    std::shared_ptr<User> m_user;
    std::shared_ptr<QWebSocket> m_websocket;
public:
    ChatWindow(std::shared_ptr<User> user, std::shared_ptr<QWebSocket> websocket, QWidget *parent = nullptr);
    ~ChatWindow();
private:
    QListWidgetItem * last_selected;
    std::map<QListWidgetItem*, long long> corresponend_list_items;
    void createCorresponentList();
private slots:
    void selectCorrespondent(QListWidgetItem* item);
    void handleResponses(QString msg);
    void requestUpdate();
    void addCorrespondent();
    void sendMessage();
private:
    Ui::ChatWindow *ui;
};
#endif // CHATWINDOW_H
