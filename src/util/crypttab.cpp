#include "crypttab.h"

#include <blkid/blkid.h>

#include <QFile>
#include <QString>
#include <QTextStream>
#include <QProcess>
#include <QTextCodec>
#include <KMessageBox>
#include <KLocalizedString>

#include "util/externalcommand.h"

#include <unistd.h>

// read /etc/crypttab
#define CRYPTTAB_COMMAND QStringLiteral("cat"), QStringList({QStringLiteral("/etc/crypttab")}), QProcess::MergedChannels
// make a file path safe to concatenate into string surrounded by '
#define MAKE_DEVICE_SAFE(deviceName) deviceName.remove(QStringLiteral("'")).remove(QStringLiteral("\\"))
// lsblk -pf '/dev/name' | grep '/dev/name' | awk '{print $4}' # get the UUID
#define LSBLK_COMMAND(deviceName) QStringLiteral("sh"), QStringList({QStringLiteral("-c"), \
    QStringLiteral("lsblk -pf '") + MAKE_DEVICE_SAFE(deviceName) + QStringLiteral("' | grep '") \
    + MAKE_DEVICE_SAFE(deviceName) + QStringLiteral("' | awk '{print $4}'")}), QProcess::MergedChannels

// Get the UUID for a given device path
static __CT_UUID_SAFE_RETURN __get_uuid_by_dev_path(QString devPath)
{
    __CT_UUID_SAFE_RETURN devContainer;
    ExternalCommand lsblkCommand(LSBLK_COMMAND(devPath));
    devContainer.status = 0;

    if (lsblkCommand.start()) {
        devContainer.devUUID = ((QString)lsblkCommand.output()).remove(QStringLiteral("\n"));
    } else {
        devContainer.status = -1;
        devContainer.devUUID = QStringLiteral("Error getting UUID");
    }

    return devContainer;
}

__CT_UUID_SAFE_RETURN CryptTabList::testThing(QString devName)
{
    return __get_uuid_by_dev_path(devName);
}

// Load all then entries in the /etc/crypttab file
void CryptTabList::loadEntries()
{
    ExternalCommand readCryptTab(CRYPTTAB_COMMAND);

    if (!readCryptTab.run()) {
        // TODO
    } else {
        QStringList cryptTabLines = readCryptTab.output().split(QStringLiteral("\n"));
        for (int j = 0; j < cryptTabLines.count(); j++) {
            CryptTabEntry newEntry = CryptTabEntry::makeFromFile(cryptTabLines[j]);
            if (newEntry.add)
                this->cryptoEntries.append(newEntry);
        }
    }
}

// Turn an entry in /etc/crypttab into a "CryptTabEntry"
CryptTabEntry CryptTabEntry::makeFromFile(QString fileEntry)
{
    CryptTabEntry newEntry;
    QStringList fileParts;
    newEntry.add = true;

    if (fileEntry.count() == 0 || fileEntry.isNull() || fileEntry.isEmpty()) {
        newEntry.add = false;
        return newEntry;
    }

    fileEntry.replace(QString(QStringLiteral(" ")),QString(QStringLiteral("\t")));
    fileParts = fileEntry.split(QString(QStringLiteral("\t")), Qt::SkipEmptyParts);

    if (fileEntry[0] == QStringLiteral("#") || fileParts.count() != 4) {
        newEntry.name = fileEntry;
        newEntry.identifier = QString(QStringLiteral(""));
        newEntry.keyFile = QString(QStringLiteral(""));
        newEntry.options = QString(QStringLiteral(""));
        newEntry.in_name_only = true;
    } else {
        newEntry.name = fileParts[0];
        newEntry.identifier = fileParts[1];
        newEntry.keyFile = fileParts[2];
        newEntry.options = fileParts[3];
        newEntry.in_name_only = false;
    }

    return newEntry;
}

// add a "CryptTabEntry" to the loaded /etc/crypttab
//  todo, forward to update if already there
void CryptTabList::createEntry(QString deviceUUID, QString deviceNode, QString deviceKeyFile, QString options)
{
    CryptTabEntry newEntry;
    newEntry.keyFile = deviceKeyFile;
    newEntry.name = deviceNode;
    newEntry.options = options;
    newEntry.identifier = QString(QStringLiteral("UUID="));
    newEntry.identifier.append(deviceUUID);
    newEntry.in_name_only = false;

    this->cryptoEntries.append(newEntry);
}

// check if the /etc/crypttab has a particular UUID mapped
bool CryptTabList::hasEntry(QString deviceUUID)
{
    bool found = false;
    QString keyValue = QString(QStringLiteral("UUID="));
    keyValue.append(deviceUUID.toLower());

    for (int j = 0; j < this->cryptoEntries.count(); j++) {
        if (keyValue.compare(this->cryptoEntries[j].identifier) == 0) {
            found = true;
            break;
        }
    }

    return found;
}

// Update the KeyFile/name(the first column) for a particular CryptTabEntry given the UUID
//  does nothing if the entry is not there
//  TODO: forward to createEntry if not there
void CryptTabList::updateEntry(QString deviceUUID, QString deviceNode, QString deviceKeyFile)
{
    QString keyValue = QString(QStringLiteral("UUID="));
    keyValue.append(deviceUUID.toLower());

    for (int j = 0; j < this->cryptoEntries.count(); j++) {
        if (keyValue.compare(this->cryptoEntries[j].identifier) == 0) {
            this->cryptoEntries[j].keyFile = deviceKeyFile;
            this->cryptoEntries[j].name = deviceNode;
            this->cryptoEntries[j].in_name_only = false;
            break;
        }
    }
}

// Calculate max column width
static void __is_new_max(int *colValue, int valueLength)
{
    if (valueLength > *colValue) {
        *colValue = valueLength;
    }
}

// Write CryptTabList to /etc/crypttab
// TODO: implement the save command as cp /etc/crypttab /etc/crypttab_bkp
//                                     printf "first line\n" > /etc/crypttab_new
//                                     each > printf "line\n" >> /etc/crypttab_new
//                                     cat /etc/crypttab_new > /etc/crypttab
//                                     rm /etc/crypttab_new
void CryptTabList::save()
{
    int cols[4] = {0,0,0,0};
    QStringList cryptTabOutput;

    this->status = 0;

    // TODO: BACKUP

    for(CryptTabEntry entry : this->cryptoEntries) {
        if(!entry.in_name_only) {
            __is_new_max(&cols[0], entry.name.length());
            __is_new_max(&cols[1], entry.identifier.length());
            __is_new_max(&cols[2], entry.keyFile.length());
            __is_new_max(&cols[3], entry.options.length());
        }
    }

    for (int j = 0; j < 4; j++)
        cols[j] += 2;

    ExternalCommand starNew(QStringLiteral("sh"), QStringList({
        QStringLiteral("-c"),
        QStringLiteral("printf '%s' '")+
        QStringLiteral("")
        +QStringLiteral("' >") + QStringLiteral("/home/el/crytithing")}));
    if(!starNew.start()) {
        this->status = -1;
        // TODO DELETE TEMP
    }


    for(CryptTabEntry entry : this->cryptoEntries) {
        QString outputItem;
        if(!entry.in_name_only) {
            outputItem = entry.compile(cols);
        } else {
            outputItem = entry.name;
        }

        ExternalCommand meow(QStringLiteral("sh"), QStringList({
        QStringLiteral("-c"),
        QStringLiteral("printf '%s\n' '")+
        outputItem.replace(QStringLiteral("'"),QStringLiteral("\\'")).replace(QStringLiteral("\""),QStringLiteral("\\\""))
            +QStringLiteral("' >>") + QStringLiteral("/home/el/crytithing")}));
        if(!meow.start()) {
            this->status = -1;
        }

    }

    // TODO: MAKE REAL
    // TODO: DELETE TEMP



    //qInfo() << QStringLiteral("NewCryptTab") << QLatin1Char('\n') << cryptTabOutput.join(QLatin1Char('\n'));

}


bool CryptTabEntry::SaveCryptTab(QWidget *parent, QString deviceNode, QString devicePath, QString deviceKeyFile)
{
    __CT_UUID_SAFE_RETURN uuidContainer;

    if ((uuidContainer = __get_uuid_by_dev_path(devicePath)).status != 0) {
        QString infoMessage = QStringLiteral("Could not get UUID for device file: <filename>")+devicePath+QStringLiteral("</filename>.") + uuidContainer.devUUID;
        KMessageBox::sorry(parent,
                   xi18nc("@info", infoMessage.toLocal8Bit().data()),
                   xi18nc("@title:window", "Error While Saving Mount Points"));
        return false;
    }

    CryptTabList ctl = CryptTabList();
    ctl.loadEntries();
    if (ctl.hasEntry(uuidContainer.devUUID)) {
        ctl.updateEntry(uuidContainer.devUUID, deviceNode, deviceKeyFile);
    } else {
        ctl.createEntry(uuidContainer.devUUID, deviceNode, deviceKeyFile, QString(QStringLiteral("luks,timeout=20")));
    }
    ctl.save();

    return ctl.status == 0 ? true : false;
}

QString CryptTabEntry::compile(int cols[4])
{
    QString output;
    output.append(this->name.leftJustified(cols[0], QLatin1Char(' ')));
    output.append(this->identifier.leftJustified(cols[1], QLatin1Char(' ')));
    output.append(this->keyFile.leftJustified(cols[2], QLatin1Char(' ')));
    output.append(this->options.leftJustified(cols[3], QLatin1Char(' ')));
    return output;
}










