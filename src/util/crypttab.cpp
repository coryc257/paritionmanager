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

#define CTE_OUTPUT qPrintable(newEntry.name), qPrintable(newEntry.identifier), qPrintable(newEntry.keyFile), qPrintable(newEntry.options)

static __CT_UUID_SAFE_RETURN __get_uuid_by_dev_path(QString devPath)
{
    __CT_UUID_SAFE_RETURN devContainer;
    QString safeDeviceName = devPath.remove(QStringLiteral("'")).remove(QStringLiteral("\\"));
    QString execCommand = QStringLiteral("lsblk -pf '") + safeDeviceName + QStringLiteral("' | grep '") + safeDeviceName + QStringLiteral("' | awk '{print $4}'");
    QProcess process;
    QStringList execArgs = {QStringLiteral("-c"),execCommand};

    devContainer.status = 0;

    process.start(QStringLiteral("sh"), execArgs);
    process.setProcessChannelMode(QProcess::MergedChannels);

    if (process.waitForFinished(-1)) {
        QByteArray x = process.readAll();
        devContainer.devUUID = QString::fromStdString(x.toStdString()).remove(QStringLiteral("\n"));
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

void CryptTabList::loadEntries()
{
    ExternalCommand readCryptTab(QStringLiteral("cat"), QStringList({QStringLiteral("/etc/crypttab")}), QProcess::MergedChannels);

    if (!readCryptTab.run()) {
        // TODO
    } else {
        QStringList cryptTabLines = readCryptTab.output().split(QStringLiteral("\n"));
        for (int j = 0; j < cryptTabLines.count(); j++) {
            printf("%d\n",j);
            this->cryptoEntries.append(CryptTabEntry::makeFromFile(cryptTabLines[j]));
        }
        /*for (QString line : cryptTabLines) {
            this->cryptoEntries.append(CryptTabEntry::makeFromFile(line));
        }*/
    }
}

CryptTabEntry CryptTabEntry::makeFromFile(QString fileEntry)
{
    CryptTabEntry newEntry;
    QStringList fileParts;


    if (fileEntry.count() == 0 || fileEntry.isNull() || fileEntry.isEmpty()) {
        newEntry.in_name_only = true;
        newEntry.name = QStringLiteral("");
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

static void __is_new_max(int *colValue, int valueLength)
{
    if (valueLength > *colValue) {
        *colValue = valueLength;
    }
}

void CryptTabList::save()
{
    int cols[4] = {0,0,0,0};
    QStringList cryptTabOutput;

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

    for(CryptTabEntry entry : this->cryptoEntries) {
        if(!entry.in_name_only) {
            cryptTabOutput.append(entry.compile(cols));
        } else {
            cryptTabOutput.append(entry.name);
        }
    }

    qInfo() << QStringLiteral("NewCryptTab") << QLatin1Char('\n') << cryptTabOutput.join(QLatin1Char('\n'));

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

    return true;
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










