# E2 Fernsteuerung

Eine Seite, die über **USB** mit einer Korg Electribe 2 redet: das Gerät fernsteuern,
sein Display live mitlesen, Effekt-Presets und Startbild ändern und das Ergebnis auf die
Speicherkarte im Gerät schreiben.

→ **[Seite öffnen](https://EliasTX09.github.io/e2-remote/)**

## Was du brauchst

- **Chrome oder Edge.** Firefox und Safari können kein Web MIDI.
- Die Seite muss über **HTTPS** laufen. GitHub Pages tut das; eine lokal geöffnete
  Datei (`file://`) funktioniert nicht.
- Eine Electribe 2 mit **BLECH-SysEx** und der **Plugin-Laufzeit** in der Firmware.
  Ohne die beiden antwortet das Gerät auf nichts davon.
- USB-Kabel und eine Speicherkarte im Gerät. Sonst nichts — kein Treiber, keine App.

## Was sie kann

| | |
|---|---|
| Verbinden | Korgs Gerätesuche (`F0 42 50 00 00 F7`), dann BLECH-INFO: Version, Fähigkeiten, größter Block |
| Fernsteuerung | alle 35 Tasten und alle 5 Drehregler, über das Befehlswort der Laufzeit |
| Display | liest das Bild aus `0xC031B310` und zeigt es, auf Wunsch laufend |
| Effekte | liest die Zeigertabellen und die Records, zeigt Name, Bausteine und Parameter, schreibt sie zurück |
| Startbild | zeigt das Bild aus dem Abbild, ersetzt es durch ein eigenes, kehrt es um |
| Karte | liest `SYSTEM.VSB` vom Gerät und schreibt sie zurück (`FILE READ` / `FILE BEGIN`) |
| Speicher | beliebige Adresse lesen, Hex-Ansicht, als Datei sichern |

## Wie Änderungen dauerhaft werden

Zwei verschiedene Wege, und der Unterschied ist wichtig:

**Tasten, Regler, Display** gehen in den Arbeitsspeicher. Ein Neustart stellt alles
wieder her.

**Effekte und Startbild** ändert die Seite im Abbild und schreibt es als `SYSTEM.VSB`
auf die Karte im Gerät. Dauerhaft wird es erst, wenn du danach am Gerät
**MENU → DATA UTILITY → SOFTWARE UPDATE** startest. Den Flash schreibt dann Korgs
eigener Updater, mit Rücklesen.

## Was sie bewusst nicht tut

**Direkt in den Flash schreiben.** Hacktribe hat dafür SysEx `0x53`/`0x56`, und BLECH
sperrt die ab. Das ist richtig so: geht ein Schreibvorgang in den Firmware-Bereich
`[0x020000, 0x220000)` mittendrin schief, startet das Gerät nicht mehr, und dann hilft
laut Quellenlage nur noch JTAG — also Löten. Der Umweg über die Karte kostet eine Minute
und kann nichts kaputt machen: passt die Datei nicht, sagt das Gerät
„Error / Invalid File" und schreibt gar nichts.

## Dateien

    index.html   Oberfläche
    e2.js        Protokoll: 8-in-7-Packung, CRC-32, Rahmen, Befehle, Datei-, Fernsteuer- und Record-Helfer

Kein Build, keine Abhängigkeiten. `e2.js` ist im Browser gegen Testvektoren geprüft:
CRC-32 von `123456789` = `0xCBF43926`, Pack-Rundlauf über 301 Bytes, die Befehlswörter
gegen die Vorlage der Laufzeit, Startbild-Umrechnung hin und zurück.
