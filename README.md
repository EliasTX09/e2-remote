# E2 Fernsteuerung

Eine Seite, die über **USB** mit einer Korg Electribe 2 redet: Effekt-Presets lesen
und umbenennen, Tasten und Rad fernsteuern, Speicher lesen und schreiben, Startbild
setzen.

→ **[Seite öffnen](https://EliasTX09.github.io/e2-remote/)**

## Was du brauchst

- **Chrome oder Edge.** Firefox und Safari können kein Web MIDI.
- Die Seite muss über **HTTPS** laufen. GitHub Pages tut das; eine lokal geöffnete
  Datei (`file://`) funktioniert nicht.
- Eine Electribe 2 mit **BLECH-SysEx** in der Firmware. Ohne die Befehle antwortet
  das Gerät auf nichts davon.
- USB-Kabel. Sonst nichts — kein Treiber, keine App.

## Was sie kann

| | |
|---|---|
| Verbinden | Korgs Gerätesuche (`F0 42 50 00 00 F7`), dann BLECH-INFO: Version, Fähigkeiten, größter Block, CRC der Schutztabelle |
| Effekt-Presets | liest die Zeigertabelle und alle 128 Records, zeigt Name und die drei Bausteine je Stufe, schreibt Namen zurück, sichert alles als Datei |
| Fernsteuerung | drückt Tasten und dreht das Rad über das Befehlswort der BLECH-Laufzeit |
| Speicher | beliebige Adresse lesen (in Blöcken bis 32 KiB), Hex-Ansicht, als Datei sichern, Datei zurückschreiben |
| Startbild | 1024 Byte ins RAM schreiben, sofort sichtbar |

## Was sie nicht kann

**Firmware flashen.** BLECH hat dafür die Befehle `0x65`/`0x66`, deren Nutzdaten
nicht nachgeprüft sind — und ein falsch geschriebenes Update macht das Gerät
unbrauchbar. Firmware kommt weiter über die SD-Karte.

## Sicherheit

Die Seite schreibt **nur ins RAM**, nie in den Flash — BLECH hat gar keinen
Flash-Schreibbefehl. Ein Neustart stellt immer alles wieder her. Was du änderst,
gilt bis zum Ausschalten; dauerhaft wird es erst, wenn du am Gerät speicherst.

Die Schutztabelle im Gerät lehnt Schreibzugriffe auf heikle Bereiche ab, bevor ein
Byte übertragen wird. Du siehst die Ablehnung als Status im Protokoll.

## Dateien

    index.html   Oberfläche
    e2.js        Protokoll: 8-in-7-Packung, CRC-32, Rahmen, Befehle, Record-Helfer

Kein Build, keine Abhängigkeiten. `e2.js` ist gegen die Standard-Testvektoren
geprüft (CRC-32 von `123456789` = `0xCBF43926`, Pack-Rundlauf über 301 Bytes).
