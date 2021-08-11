
#ifndef CRYPTTABL_H
#define CRYPTTABL_H

#include <fs/filesystem.h>
#include <util/capacity.h>

#include <vector>
#include <QList>
#include <QWidget>

typedef struct __CT_UUID_SAFE_RETURN {
    int status;
    QString devUUID;
} __CT_UUID_SAFE_RETURN;

class QString;

class CryptTabEntry
{
public:
    QString name;
    QString identifier;
    QString keyFile;
    QString options;
    bool in_name_only;

    static CryptTabEntry makeFromFile(QString fileEntry);
    static bool SaveCryptTab(QWidget *parent, QString deviceNode, QString deviceUUID, QString deviceKeyFile);
    QString compile(int cols[4]);
};

class CryptTabList
{
public:
    QList<CryptTabEntry> cryptoEntries;

    void loadEntries(void);
    bool hasEntry(QString deviceUUID);
    void updateEntry(QString deviceUUID, QString deviceNode, QString deviceKeyFile);
    void createEntry(QString deviceUUID, QString deviceNode, QString deviceKeyFile, QString options);
    void save();
    static __CT_UUID_SAFE_RETURN testThing(QString devName);

    CryptTabList()
    {

    }
};

#endif
