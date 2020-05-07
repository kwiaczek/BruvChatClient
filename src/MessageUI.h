#ifndef MESSAGEUI_H
#define MESSAGEUI_H

#include <string>
#include <Qstring>

struct MessageUI{
    std::string from;
    std::string message;
    MessageUI(std::string _from, std::string _message)
    {
        if(_from == "You")
        {
            from = "<font color=\"Blue\"><b>";
            from += _from;
            from += "</b></font>";
        }
        else
        {
            from = "<font color=\"Red\"><b>";
            from += _from;
            from += "</b></font>";
        }

        message = _message;
    }
    QString format()
    {
        return QString::fromStdString(("<h4>" + from +": " + message + "</h4>"));
    }
};

#endif // MESSAGEUI_H
