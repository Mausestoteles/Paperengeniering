# Security Audit – Hardened Paper Distribution

Basis: upstream [PaperMC/Paper](https://github.com/PaperMC/Paper) Commit `e5aa18b3189fef92c2fbcff8ab5fe9beafd02152`
(Minecraft 26.3, Java 25). Das Repository wurde vor der Härtung byte-identisch gegen Upstream geprüft — **alle Befunde
betreffen daher auch Upstream Paper**, nichts davon wurde durch eigene Änderungen eingeschleppt.

Methodik: 12 unabhängige Code-Audits (Command-Dispatch, Paket-Handler ×3, Auth/Proxy/RCON/JSON-RPC, Plugins/Permissions/
Dateisystem, Netzwerk-Decoding/Crash, Gameplay-Crash, Duplication ×4). Jeder hier gelistete Befund wurde anschließend
manuell im Code verifiziert, bevor er gefixt wurde. Nicht verifizierbare / spekulative Punkte sind entsprechend markiert.

Alle Code-Änderungen sind mit `Hardening` im Kommentar markiert (`// Hardening ...` bzw. `// Paper start - Hardening`).

Legende Schweregrad: **Critical / High / Medium / Low / Info**. PoC = Proof of Concept (Reproduktionsschritte; bewusst
so beschrieben, dass sie zum Nachtesten auf dem eigenen Server reichen, aber kein fertiges Angriffstool sind).

---

## 1. Crash / Denial of Service

### 1.1 Overfilled Bundle crasht Server-Tick beim Encoden (HIGH, verifiziert, gefixt)
- **Datei:** `paper-server/src/main/java/io/papermc/paper/util/sanitizer/OversizedItemComponentSanitizer.java` (`sanitizeBundleContents`)
- **Fehler:** Der Item-Obfuscation-Sanitizer (Standard `OVERSIZED`) baut pro 64 Gewichtseinheiten einen Papier-Stack und
  erzeugt daraus `new BundleContents(list)`. Paper's eigenes Limit in `BundleContents` wirft ab 256 Einträgen
  `IllegalArgumentException("Too many items")`. Zusätzlich: `Mth.mulAndTruncate` rechnet `numerator * 64` als `int`
  (Overflow) und `weight().getOrThrow()` wirft bei Fehler-Gewicht.
- **Auswirkung:** Auf einem Regal (`ShelfBlockEntity.getUpdateTag`) → Exception im Main-Thread beim Chunk-/BlockEntity-
  Paketbau → **Server-Crash, bei jedem Neustart erneut sobald der Chunk geladen wird**. In Item-Frame / Drop /
  Equipment → Exception im Netty-Encoder → **alle Zuschauer werden gekickt** (permanente "Kick-Zone").
- **PoC:** Creative-Spieler (oder `/give`/Plugin) erzeugt Bundle mit 256 inneren Bundles à 64 Erde
  (Gewicht 256·(1+1/16)=272 → 272 Einträge > 256). Bundle auf Regal legen oder in Item-Frame stecken.
- **Fix:** Gewicht in `long` berechnen, Fehler-Gewicht als 1 behandeln, Ergebnis auf 256·64 clampen.

### 1.2 LegacyQueryHandler leakt Netty-Buffer pro Verbindung (MEDIUM-HIGH, reproduziert, gefixt)
- **Datei:** `net/minecraft/server/network/LegacyQueryHandler.java` (`channelRead` finally-Block)
- **Fehler:** `readLegacy1_6()` entfernt bei ungültigem Channel-String / Host / Trailing-Bytes den Handler selbst aus der
  Pipeline (`removeHandler`) und gibt `null` zurück. `channelRead` läuft danach in `finally` mit `connectNormally == true`
  und ruft `pipeline().remove(this)` ein zweites Mal → `NoSuchElementException`, der eingehende `ByteBuf` wird nie
  released und nie weitergereicht.
- **Auswirkung:** Pro ~14 Bytes + TCP-Handshake ein permanent geleakter pooled Direct-Buffer (2–64 KB), unauthentifiziert,
  vor dem Handshake (Connection-Throttle greift nicht). Loop → `OutOfDirectMemoryError` in den Event-Loops → Netzwerk tot.
- **PoC:** TCP-Verbindung zum Spielport, Bytes `FE 01 00 00 01 00 41 00 00 00 00 00 00 00` senden, Verbindung
  schließen, wiederholen. (Reproduziert mit Netty `EmbeddedChannel`: `exceptionCaught: NoSuchElementException`,
  `msg refCnt == 1` nach dem Read.)
- **Fix:** Im `finally` prüfen ob `ctx.isRemoved()`; dann nur `in.release()`.

### 1.3 RCON: unbegrenzte Clients, ein Thread pro Verbindung, kein Timeout (MEDIUM, verifiziert, gefixt)
- **Datei:** `net/minecraft/server/rcon/thread/RconThread.java`, `RconClient.java`
- **Fehler:** `accept()` ohne Limit, `setSoTimeout(0)` → jede offene Verbindung blockiert einen Platform-Thread für immer.
- **PoC:** Tausende TCP-Verbindungen zum RCON-Port öffnen und nichts senden → `OutOfMemoryError: unable to create native thread`.
- **Fix:** 30 s Read-Timeout, max. 16 gleichzeitige Clients (`-Dpaper.rcon.maxClients`), s. auch 2.6.

### 1.4 RCON: negative String-Länge bei kurzen AUTH-Paketen (LOW, verifiziert, gefixt)
- **Datei:** `RconClient.run` → `PktUtils.stringFromByteArray(buf, 12, read)`
- **PoC:** 10-Byte-Paket `06 00 00 00 | 00 00 00 00 | 03 00` → `new String(b, 12, -3)` → `StringIndexOutOfBoundsException`,
  wird pro Verbindung mit Stacktrace auf ERROR geloggt (Log-Flooding).
- **Fix:** `if (offset > read) return;` vor dem `switch`.

### 1.5 Permission-Zyklus → StackOverflowError bei jeder Neuberechnung (LOW-MEDIUM, verifiziert, gefixt)
- **Datei:** `paper-api/src/main/java/org/bukkit/permissions/PermissibleBase.java` (`calculateChildPermissions`)
- **PoC:** `permissions.yml`: `a: {children: {b: true}}`, `b: {children: {a: true}}` → jeder Join / op-Wechsel /
  Attachment wirft `StackOverflowError`, Spieler können nicht mehr joinen.
- **Fix:** Rekursionspfad-Set; ein Kind, das bereits auf dem aktuellen Pfad liegt, wird nicht erneut expandiert.

### 1.6 HAProxy `HAProxyMessage` wird nie released (LOW, verifiziert, gefixt)
- **Datei:** `net/minecraft/server/network/ServerConnectionListener.java` (`haproxy-handler`)
- Nur relevant bei `proxy-protocol: true`. Langsames Speicherwachstum bei Verbindungsfluten. Fix: `try/finally message.release()`.

### 1.7 BungeeCord-Handshake macht DNS-Lookups im Netty-Thread (LOW, verifiziert, gefixt)
- **Datei:** `net/minecraft/server/network/ServerHandshakePacketListenerImpl.java`
- **Fehler:** `HOST_PATTERN = [0-9a-f\.:]{0,45}` akzeptiert Hostnamen wie `dead.beef.cafe` oder leeren String →
  `new InetSocketAddress(String, int)` macht blockierenden DNS-Lookup im Event-Loop.
- **Fix:** `InetAddresses.forString()` (nur IP-Literale), sonst Disconnect "Invalid forwarded address".

### 1.8 Login-Query-Antwort in pooled Direct-Buffer kopiert (LOW, spekulativ, gehärtet)
- **Datei:** `net/minecraft/network/protocol/login/ServerboundCustomQueryAnswerPacket.java`
- Bis 1 MiB pro Paket aus dem Pool; Release nur wenn der Handler tatsächlich läuft (nicht bei `stopReadingPackets`/DROP).
  Fix: Heap-Kopie (`Unpooled.copiedBuffer`), GC räumt fallengelassene Pakete auf.

### 1.9 `ByteBufCodecs.increaseDepth` dekrementiert nie (LOW, Korrektheit, gefixt)
- Zählt Gesamtzahl verschachtelter Codecs statt aktueller Tiefe → breite, legitime Creative-Items werden als "Too deep"
  abgelehnt. Fix: `finally { codecDepth-- }`.

---

## 2. Authentifizierung / Admin-Schnittstellen

### 2.1 Ein fehlerhafter Ban-Eintrag löscht alle folgenden Bans (MEDIUM, fail-open, verifiziert, gefixt)
- **Dateien:** `net/minecraft/server/players/StoredUserList.java` (`load`), `UserBanListEntry.java` (`parseNameAndId`)
- **Fehler:** Eintrag ohne / mit undashed UUID → `uuid == null` → `getKeyForUser` NPE → Spigot-Catch benennt
  `banned-players.json` in `.backup` um und löscht sie; die Map war vorher geleert → nur Einträge *vor* dem defekten
  bleiben, nächstes `save()` schreibt die verkürzte Liste.
- **PoC:** In `banned-players.json` einen Eintrag mit `"uuid": "069a79f444e94726a5befca90e38aaf5"` (ohne Bindestriche)
  an Position 2 einfügen, Server neu starten → alle Bans ab Position 3 sind weg.
- **Fix:** Pro Eintrag try/catch (überspringen + Warnung), Laden in temporäre Map und erst bei Erfolg swappen;
  undashed UUIDs werden akzeptiert.

### 2.2 Offline-Mode ohne Proxy: keinerlei Username-Validierung (LOW-MEDIUM, verifiziert, gefixt)
- **Datei:** `ServerLoginPacketListenerImpl.handleHello`
- **Fehler:** Paper ersetzte Vanillas unbedingtes `isValidPlayerName` durch einen Check, der nur bei
  `isProxyOnlineMode()` läuft. Ohne Proxy sind leere Namen, Leerzeichen, `\n`/`\r`, ESC (0x1b), `§` erlaubt.
- **PoC:** Offline-Server, Client mit Name `"Steve\n[Server] op hacker"` → gefälschte Konsolenzeilen in `latest.log`;
  ESC-Sequenzen erreichen das Admin-Terminal ungefiltert.
- **Fix:** Vanilla-Baseline-Check immer (außer bei explizitem Override-Flag), strengerer Check zusätzlich im Proxy-Modus.

### 2.3 Jeder `PlayerHandshakeEvent`-Listener schaltet BungeeCord-Forwarding ab (LOW, verifiziert, gefixt — Verhaltensänderung)
- **Datei:** `ServerHandshakePacketListenerImpl`
- **Fehler:** Bei `bungeecord: true` startet das Event *uncancelled*; ein Plugin, das nur zuhört (z. B. Logging), setzt
  `handledByEvent = true` → Forwarding-Parsing wird übersprungen → alle Spieler haben Proxy-IP (IP-Bans treffen alle)
  und Offline-UUIDs.
- **Fix:** Als "handled" gilt das Event nur, wenn der Listener Hostname, Socket-Adresse, UUID oder Properties gesetzt hat.
  *Hinweis:* Plugins, die bewusst "nichts setzen" wollten, verhalten sich jetzt wie ohne Listener.

### 2.4 RCON-Passwort per `String.equals`, kein Brute-Force-Schutz (LOW, verifiziert, gefixt)
- Fix: `MessageDigest.isEqual` (constant-time), nach 3 Fehlversuchen Verbindung schließen, wachsende Verzögerung.

### 2.5 Velocity-Forwarding replaybar (INFO, Design, nicht fixbar ohne Protokolländerung)
- HMAC deckt nur die Forwarding-Daten ab, nicht die zufällige `velocityLoginMessageId` des Backends. Wer den
  unverschlüsselten Proxy→Backend-Traffic einmal mitliest, kann den Blob gegen ein erreichbares Backend replayen.
- **Empfehlung:** Backends ausschließlich an private Interfaces binden / Firewall. Der HMAC-Vergleich selbst ist
  constant-time und korrekt.

### 2.6 Geprüft und korrekt
- Velocity: constant-time HMAC, leeres Secret deaktiviert, Version > 4 abgelehnt, IPs ohne DNS, direkte Offline-Logins
  bei aktivem Velocity abgelehnt.
- Online-Mode-Auth (`hasJoinedServer`) unverändert; `profileId` aus dem Client-Paket wird nie vertraut.
- JSON-RPC-Management-Server: standardmäßig aus, `localhost`, TLS, 40-Zeichen-Secret, constant-time, Origin-Allowlist.
- Whitelist/Ops per UUID; Konsole `has-all-permissions: false`.

---

## 3. Privilege Escalation / Permissions

### 3.1 `removePermission` lässt alte Defaults aktiv (MEDIUM, verifiziert, gefixt)
- **Datei:** `paper-server/src/main/java/io/papermc/paper/plugin/manager/PaperPermissionManager.java`
- **Fehler:** Entfernt nur aus `permissions()`, nicht aus `defaultPerms()`. `getDefaultPermissions(op)` liefert die
  Permission weiter, `PermissibleBase.recalculatePermissions()` vergibt sie und alle Kinder weiter.
- **PoC:** Plugin registriert `myplugin.admin` mit `default: true` (Fehler), Admin korrigiert per
  `removePermission` + `addPermission(..., OP)` oder Plugin-Reload mit korrigierter `plugin.yml` → jeder Nicht-Op
  behält `myplugin.admin` bis zum Neustart.
- **Fix:** Auch aus beiden Default-Sets entfernen und betroffene Permissibles neu berechnen.

### 3.2 Plugin-Library-Resolver akzeptiert `http://`-Repositories (MEDIUM → RCE via MITM, verifiziert, gefixt)
- **Datei:** `paper-api/src/main/java/io/papermc/paper/plugin/loader/library/impl/MavenLibraryResolver.java`
- **Fehler:** `addRepository` prüft das Schema nicht; `CHECKSUM_POLICY_FAIL` hilft nicht, weil die `.sha1` über denselben
  unauthentifizierten Kanal kommt. `PAPER_DEFAULT_CENTRAL_REPOSITORY` konnte ebenfalls `http://` sein.
- **PoC:** Plugin-Loader mit `http://repo.example.com/` → Angreifer im Netzwerkpfad tauscht das JAR beim ersten Start →
  beliebiger Code in der Server-JVM.
- **Fix:** Nur `https://` (und `file:`) erlaubt; Override per `-Dpaper.allowInsecureLibraryRepositories=true`.
  Unsichere Central-Overrides werden ignoriert (Log-Error).

### 3.3 `/paper`-Tab-Completion umgeht Subcommand-Permission (LOW, Info-Leak, verifiziert, gefixt)
- `execute()` prüft `paper.command.<sub>`, `tabComplete()` nicht → mit nur `paper.command.mobcaps` bekommt man
  Completions von `entity`, `dumplisteners` (alle Event-Klassen) etc. Fix: gleicher Check, still.

### 3.4 `/paper dumplisteners <class>` initialisiert beliebige Klassen (LOW, verifiziert, gefixt)
- `Class.forName(className)` mit Initialisierung + Reflection auf statisches `getHandlerList()` beliebiger Klassen.
  Fix: ohne Initialisierung laden, nur `org.bukkit.event.Event`-Subklassen zulassen.

### 3.5 Plugin-Name `.` / `..` erlaubt → Datenordner außerhalb `plugins/` (LOW, verifiziert, gefixt)
- `PluginDescriptionFile.VALID_NAME` und `PluginConfigConstraints` akzeptierten `..` → `new File(plugins, "..")` = Server-
  Root; `saveDefaultConfig()` schreibt dorthin. Fix: Regex mit Negative-Lookahead `^(?!\.+$)...`.

### 3.6 `DefaultPermissions.registerPermission(perm, withLegacy)` registriert die Legacy-Permission nie (LOW, Korrektheit, gefixt)
- Rief `registerPermission(perm, false)` statt `registerPermission(legacy, false)` auf.

### 3.7 Geprüft und korrekt (Command-/Permission-System)
- Alle sensiblen Bukkit-Permissions defaulten auf OP oder FALSE; einzige TRUE-Defaults: `minecraft.command.{me,msg,help,
  trigger,teammsg}`, `bukkit.command.{help,plugins,version}`, `bukkit.broadcast.user`, `minecraft.nbt.copy`.
- Vanilla-Command-Bridge mappt Root-Requirement auf `minecraft.command.<root>` inkl. Redirects; Command-Blocks
  `force-follow-perm-level: true` (Level 2, kein `/op`).
- YAML-Deserialisierung via `SafeConstructor`; kein `ObjectInputStream` serverseitig.
- Creative-Set-Slot nur mit `hasInfiniteMaterials()`; `block_entity_data` für Command-Block/Lectern/Sign/Spawner und
  `entity_data` für FallingBlock/Command-Minecart/Spawner-Minecart nur mit Op / `minecraft.nbt.place` (OP-Default).
- Command-/Structure-/Jigsaw-/Test-Block-Pakete, Tag-Queries, Gamemode/Gamerule/Difficulty-Pakete, Debug-Subscriptions:
  korrekt gegated. Sign-Edit: Formatierung gestrippt, nur eigener `playerWhoMayEdit`, `run_command` nur bei
  `allow_op_features` (nicht ohne Op platzierbar). Book-Edit: reine Strings, keine Components.

### 3.8 Hinweise für Admins (kein Bug)
- `minecraft.commandblock` gibt faktisch Level-2-Command-Ausführung (`/give`, `/tp`, `/execute`) — nicht an Builder-
  Gruppen vergeben.
- `bukkit.command.plugins` / `version` (TRUE) verraten Plugin-Liste und Version; `query-plugins: true` in `bukkit.yml`
  ebenfalls, sobald `enable-query=true`. Ggf. auf OP setzen.
- Paper-Click-Callbacks (`ClickCallbackProviderImpl`) sind an eine zufällige UUID, nicht an den Empfänger gebunden.
  Plugins müssen im Callback die Berechtigung des tatsächlichen Klickenden erneut prüfen.
- Dialog-Antworten (`DialogClickManager`) erreichen Plugins unvalidiert (Werte außerhalb des erlaubten Bereichs).

---

## 4. Duplication (Items / Variablen)
_(wird nach Abschluss der vier Dupe-Audits ergänzt)_

---

## 5. Noch offene / nicht gefixte Punkte
- 2.5 Velocity-Replay (Protokolländerung nötig).
- 3.8 Click-Callback-Bindung an Empfänger (API-Änderung; als Härtungsoption vorgemerkt).
- Dimension-Keys als Ordnerpfade in `CraftServer.createWorld` (nur Plugin-/Datapack-kontrolliert; `..`-Segmente
  ablehnen wäre sinnvoll).
