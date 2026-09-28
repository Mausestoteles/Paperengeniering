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

### 3.0 Command-Blöcke können `/op`, `/stop`, `/ban` ausführen – `force-follow-perm-level` war tot (HIGH, verifiziert, gefixt)
- **Dateien:** `net/minecraft/commands/CommandSourceStack.java` (`forceRespectPermissionLevel`, `hasPermission`),
  `net/minecraft/world/level/BaseCommandBlock.java`
- **Fehler:** Paper's Check prüfte `this.source instanceof BaseCommandBlock`. In dieser Minecraft-Version implementiert
  `BaseCommandBlock` aber kein `CommandSource` mehr – die tatsächliche Quelle ist die innere Klasse
  `BaseCommandBlock.CloseableCommandBlockSource`. Der `instanceof` war damit **immer false**, die Option
  `command-blocks.force-follow-perm-level: true` (Default) und `permissions-level: 2` wirkungslos. Da der Bukkit-Sender
  eines Command-Blocks (`CraftBlockCommandSender` / `CraftMinecartCommand`) immer Op ist und alle
  `minecraft.command.*`-Permissions auf OP defaulten, ging jede Vanilla-Berechtigungsprüfung durch (`hasPermLevel ||
  hasBukkitPerm`). Zusätzlich übersprang `commands.yml → ignore-vanilla-permissions: true` den erzwungenen Level-Check
  komplett (auch für Datapack-Functions mit NULL-Source).
- **PoC:** Als Level-2-Op oder als Creative-Builder mit `minecraft.commandblock` einen Impulse-Command-Block mit
  `op <eigener Name>` (oder `stop`, `deop <Admin>`, `whitelist off`) setzen und mit Redstone auslösen → wird ausgeführt,
  obwohl Command-Blöcke auf Level 2 begrenzt sein sollten.
- **Fix:** `instanceof CloseableCommandBlockSource` + Level-Accessor; der erzwungene Level-Check läuft jetzt **vor** dem
  `ignore-vanilla-permissions`-Zweig.
- **Admin-Hinweis (Design):** Der Bukkit-Sender von Command-Blöcken bleibt Op → Plugin-Commands (z. B. LuckPerms
  `/lp user X permission set *`) sind über Command-Blöcke weiterhin ausführbar. `minecraft.commandblock` ist damit
  faktisch Voll-Admin.

### 3.0a Dialog-Click-Callbacks: jeder Client kann jeden Registry-Dialog-Callback auslösen (MEDIUM, verifiziert, gefixt)
- **Dateien:** `io/papermc/paper/adventure/providers/ClickCallbackProviderImpl.java`, `ServerCommonPacketListenerImpl`,
  neu: `io/papermc/paper/dialog/DialogCallbackCollector.java`
- **Fehler:** `DialogAction.customClick(callback)` speichert den Callback in einer globalen Map, nur mit einer zufälligen
  UUID als Schlüssel. Dialoge im (synchronisierten) Dialog-Registry werden **an jeden Client** in der Config-Phase
  gesendet – inklusive der Callback-UUIDs. `handleCustomClickAction` prüfte nicht, ob der Dialog dem Spieler je gezeigt
  wurde, und funktionierte auch in der Config-Phase.
- **PoC:** Plugin registriert einen Admin-Dialog ("Spieler bannen") im Registry und öffnet ihn nur für Ops. Ein
  Modded-Client liest die UUID aus den Registry-Daten und sendet
  `ServerboundCustomClickAction(paper:dialog_click_callback, {id: <uuid>, name: "Owner"})` → Callback läuft mit dem
  Angreifer als Audience und frei gewählten Antwortfeldern. Mit `uses(1)` kann ein Client den Button außerdem für alle
  verbrauchen (DoS).
- **Fix:** Beim Senden eines `ClientboundShowDialogPacket` werden alle Callback-IDs des Dialogs (rekursiv, inkl.
  `DialogListDialog`) pro Verbindung gesammelt; `ClientboundClearDialogPacket` leert die Liste. Ein Dialog-Callback
  läuft nur, wenn seine ID für diese Verbindung freigegeben ist.
- **Offen (Design):** Adventure-`ClickCallback`s in Chat-Components sind weiterhin nur durch die zufällige UUID
  geschützt (nicht an Empfänger gebunden). Plugins müssen im Callback die Berechtigung des Klickenden prüfen.
  Dialog-Antworten (`PaperDialogResponseView`) sind weiterhin unvalidiert (Zahlen außerhalb des Sliders, überlange
  Strings, fremde Keys) – Plugins müssen validieren.

### 3.0b Weitere Paket-Härtungen (LOW, verifiziert, gefixt)
- **Attack/Interact ignorieren `Player#canSee`:** Entity-IDs sind sequenziell; ein Spieler konnte per Brute-Force
  einen gevanishten Admin schlagen oder Items von versteckten Armor-Stands nehmen (`handleAttack`, `handleInteract`).
  Fix: `canSee`-Check (inkl. EnderDragon-Parts).
- **`TradeSelectEvent` vor `stillValid` und ohne Index-Check:** negative/zu große Indizes erreichten Plugins →
  Exceptions/Log-Spam. Fix: Menü- und Index-Validierung vor dem Event.
- **Lectern-Seitensprung (`buttonId >= 100`) umging `PlayerLecternPageChangeEvent`:** Plugins, die Seiten sperren,
  waren umgehbar. Fix: Event auch für Sprünge.
- **`UncheckedSignChangeEvent` für beliebige Positionen:** Plugins mit virtuellen Schildern als Eingabe bekamen Eingaben
  aus 10 000 Blöcken Entfernung. Fix: 64-Block-Reichweitenprüfung.
- **View-Distance in der Config-Phase unvalidiert:** negativer Wert landete in `getClientViewDistance()`. Fix wie in
  der Game-Phase (Disconnect).
- **`finishCurrentTask` off-main:** Nach `AsyncPlayerConnectionConfigureEvent` lief der Task-Wechsel (inkl.
  `PrepareSpawnTask`, Spieler-Daten laden) auf einem Virtual-Thread. Fix: auf den Main-Thread umleiten.
- **Cookie-API:** `retrieveCookie` überschrieb ausstehende Futures (hängender `join()`), `get`+`remove` nicht atomar.
  Fix: `putIfAbsent`/`remove`. *Hinweis:* Cookies sind clientkontrolliert – niemals als Authentifizierung ohne HMAC nutzen.
- **Lectern resolved Bücher auf GAMEMASTER-Level** (nur bei `item-validation.resolve-selectors-in-books: true`, Default
  aus): `@e`, `nbt`-/`storage`-Selektoren in Spielerbüchern würden serverseitig mit Level 2 aufgelöst → Info-Leak.
  Nicht geändert; Option nicht aktivieren.
- **Commands-Packet sendet Kinder "toter" Redirects ungefiltert** (Info-Leak von Subcommand-Layouts ohne Permission,
  `Commands.fillUsableCommands`). Nicht geändert (nur Disclosure, Ausführung bleibt geprüft).

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

Ergebnis: **Ohne Plugins wurde kein von Spielern auslösbarer Dupe gefunden.** Alle `unsupported-settings`-Dupe-Toggles
(`allow-piston-duplication`, `allow-headless-pistons`, `allow-permanent-block-break-exploits`,
`allow-unsafe-end-portal-teleportation`) stehen auf dem sicheren Default und ihr Guard-Code deckt alle Varianten ab
(TNT/Slime, Rails/Carpets, Gravity-Blocks am End-Portal). Die folgenden Dupes sind real, benötigen aber ein Plugin,
das auf ein Event in bestimmter Weise reagiert – auf typischen Servern (Shop-, Trade-Limiter-, Protection-Plugins)
sind sie damit praktisch erreichbar.

### 4.1 Abgebrochener Villager-/Merchant-Trade: Ergebnis landet trotzdem am Cursor, Bezahlung bleibt (HIGH, verifiziert, gefixt)
- **Dateien:** `world/inventory/AbstractContainerMenu.java` (PICKUP-Zweig "gleiches Item am Cursor"),
  `world/inventory/MerchantResultSlot.java`
- **Fehler:** Im PICKUP-Zweig wurde `carried.grow(itemsTaken.getCount())` **vor** `slot.onTake(...)` ausgeführt. Bricht
  ein Plugin `PlayerTradeEvent`/`PlayerPurchaseEvent` ab, wird nur `itemsTaken` genullt – der Cursor war schon gewachsen.
  `tryRemove` → `setChanged()` füllt den Result-Slot sofort wieder.
- **PoC:** Plugin, das `PlayerTradeEvent` cancelt (Trade-Limiter, Shop-Permission-Check). Gültige Bezahlung einlegen,
  dasselbe Item wie das Trade-Ergebnis am Cursor halten, Result-Slot linksklicken → Cursor wächst um das Ergebnis,
  Bezahlung bleibt. Beliebig wiederholbar.
- **Fix:** `onTake` zuerst, dann `grow`. Zusätzlich: schlägt `offer.take()` fehl (z. B. Plugin erhöht im Event den
  Preis), wird das Ergebnis genullt statt ausgehändigt, und Villager-XP wird nur bei Erfolg vergeben.

### 4.2 Hopper `InventoryMoveItemEvent`: Plugin erhält den Live-Stack des Quell-Slots (HIGH bei Move-Listenern, verifiziert, gefixt)
- **Datei:** `world/level/block/entity/HopperBlockEntity.java` (Paper-Patch 0034 "Optimize Hoppers")
- **Fehler:** `callPushMoveEvent`/`callPullMoveEvent` übergaben `asBukkitMirror(stack)` des noch im Quell-Slot liegenden
  Stacks. (a) `event.getItem().setAmount(64)` änderte die Instanz, die anschließend in den Ziel-Slot wanderte; die Quelle
  wurde als `original - moved + remaining` zurückgeschrieben → 10 Items werden 73. (b) Bei `setItem(ersatz)` mit
  größerer Anzahl als `hopperAmount` wurde der Rest des **Ersatzes** auf die Quelle (mit deren Item-Typ) addiert.
- **PoC:** Listener auf `InventoryMoveItemEvent` mit `e.getItem().setAmount(64)`; Hopper unter einer Kiste mit 10
  Cobblestone, leere Kiste darunter → Kiste unten 64, Kiste oben 9.
- **Fix:** Event bekommt eine Kopie; Mutation via `getItem()` wird wie `setItem()` behandelt; bei Ersatz-Stack wird der
  Quelle nie etwas gutgeschrieben (`replaced ? 0 : remaining`); "nichts bewegt" wird gegen die tatsächliche
  Startmenge des bewegten Stacks geprüft.

### 4.3 `InventoryDragEvent` + Plugin schließt Inventar → Rest wird doppelt zurückgegeben (MEDIUM, verifiziert, gefixt)
- **Datei:** `AbstractContainerMenu.java` (Drag-Ende)
- **Fehler:** Vor dem Event wird der Cursor auf den nicht verteilbaren Rest gesetzt. Schließt ein Listener das Inventar
  (Anti-Cheat/GUI-Plugins), legt `removed()` diesen Rest ins Inventar und leert den Cursor. Nach dem Event wurde der
  Cursor erneut gesetzt (erlaubt: `event.getCursor()`, verweigert: alter Cursor) → Rest existiert zweimal.
- **PoC:** Plugin mit `player.closeInventory()` in `InventoryDragEvent`. Im eigenen Inventar 64 Cobblestone über zwei
  Slots mit je 60 ziehen → Rest 56 im Inventar **und** am Cursor.
- **Fix:** Erkennung "während des Events geschlossen" (Menü gewechselt oder Cursor-Instanz ersetzt) → Cursor nicht
  erneut setzen; im Deny-Fall nur den tatsächlich gezogenen Anteil zurückgeben.

### 4.4 Mending: gesenkter `setRepairAmount` repariert gratis + StackOverflow (MEDIUM, verifiziert, gefixt)
- **Datei:** `world/entity/ExperienceOrb.java` (`repairPlayerItems`)
- **Fehler:** `remaining = amount - repair*amount/toRepair` rundet ab. Setzt ein Plugin `PlayerItemMendEvent#setRepairAmount(1)`
  ("Slow Mending"), ist der XP-Verbrauch 0 → `remaining == amount` → Rekursion pro Durability-Punkt bis alles repariert
  ist, und die **volle** XP wird trotzdem gutgeschrieben. Rekursionstiefe = Gesamtschaden → StackOverflowError im
  Tick-Thread bei großem `max_damage`. `toRepairFromXpAmount == 0` (Datapack-Enchantment) → Division durch Null.
- **Fix:** mind. 1 XP pro Reparaturvorgang (`ceil`), Division-durch-Null-Guard.

### 4.5 XP-Orb mit `count <= 0` gibt endlos XP; `merge` Integer-Overflow (MEDIUM bei API-Missbrauch, gefixt)
- `CraftExperienceOrb.setCount` ohne Prüfung; `playerTouch` verwarf nur bei `count == 0`; `merge` addierte ohne
  Overflow-Schutz. Fix: `count > 0` erzwingen, `<= 0` verwerfen, `merge` in `long`.

### 4.6 Negative `Inventory#setMaxStackSize` + `ItemStack.split(negativ)` vergrößert Quell-Stack (MEDIUM bei API-Missbrauch, gefixt)
- Hotbar-Swap in leeren Slot ruft `source.split(-k)` → `shrink(-k)` → Quelle wächst. Fix: `size >= 1` erzwingen,
  `split` clampt auf `[0, count]`.

### 4.7 Advancement-Rewards doppelt bei re-entrantem `award` (LOW-MEDIUM, verifiziert, gefixt)
- `PlayerAdvancements.award`: `wasDone` wird vor `PlayerAdvancementCriterionGrantEvent` gelesen. Vergibt ein Listener das
  letzte Kriterium selbst, gewähren innerer und äußerer Aufruf beide die Rewards (Loot, Function). Fix: `rewarded`-Set
  als Guard, in `revoke` zurückgesetzt.

### 4.8 Weitere Korrekturen
- **Menü-Sync stoppt nach ungültigem Slot-Index** (`handleContainerClick`): `suppressRemoteUpdates()` lief vor dem
  Early-Return für `slotNum < -1` → keine Slot-Updates mehr bis zum nächsten gültigen Klick (Ghost-Items). Gefixt.
- **Dispenser-Bucket-Pickup** vertraute einem Dry-Run vor `BlockDispenseEvent`; änderte ein Plugin die Ziel-Flüssigkeit,
  gab es trotzdem einen vollen Eimer und AIR über dem neuen Block. Fix: Zustand nach dem Event neu lesen, nur das
  tatsächlich Aufgenommene ausgeben.

### 4.8a Entity-/Persistenz-Härtungen (LOW, verifiziert, gefixt)
- **Pferd/Esel/Lama-Inventar wird nach dem Tod nicht geleert** (`AbstractHorse.dropEquipment`): Paper spawnt Drops als
  Kopien nach dem Death-Event; Allay/Piglin leeren ihr Inventar via `postDeathEventTasks`, Pferde nicht. Wird das Tier
  innerhalb der 20-Tick-Todesanimation wiederbelebt (`/data merge … Health`, Plugin `setHealth`), hat es die volle Kiste
  **und** die Drops liegen am Boden. Fix: Inventar wie bei Allay/Piglin leeren.
- **Duplicate-UUID-Resolver nutzt `discard()`** (`ChunkStatusTasks`): `DISCARDED.shouldDestroy() == true` → ein
  abgelehntes Duplikat einer Kisten-/Hopper-Lore oder eines Kisten-Boots verschüttet seinen Inhalt, während das
  Original ihn behält (nur Proto-Chunk-Loads, z. B. kopierte Legacy-Regionsdateien). Fix: `setRemoved(UNLOADED_WITH_PLAYER)`.
- **API-geöffnete Reittier-Menüs umgingen Lebens- und `hasInventoryChanged`-Check** (`AbstractMountInventoryMenu`):
  `openInventory(horse.getInventory())` setzt `checkReachable=false` → `stillValid` gab immer `true`. Nach
  `createInventory()` (`/data merge`, `/item replace`) konnte aus dem veralteten Container genommen werden, während die
  Kopien am Tier blieben. Fix: Reach-Bypass bleibt, Validitäts-Bypass nicht.

### 4.9 Design-Hinweise (nicht geändert)
- **Crash-Window-Rollback (inhärent):** Spieler werden per `player-auto-save.rate`, Chunks bei Unload/Autosave
  gespeichert. Jeder Crash/Watchdog-Kill kann einen Chunk (Kisteninhalt) älter als die Spielerdatei wiederherstellen.
  → Jeder Crash-Vektor ist ein Dupe-Vektor; `player-auto-save.rate` kurz halten.
- `Container.stillValidBlockEntity` prüft keine Welt-Gleichheit (nur Distanz) – nach Portal nahe 0,0 ist ein Overworld-
  Container aus dem Nether nutzbar (kein Dupe, da Unload Viewer schließt).
- `ServerPlayer.closeUnloadedInventory` verliert das Cursor-Item (Verlust, kein Dupe).
- `BlockDispenseEvent#setItem`: Ersatz wird dispensiert, Original nicht verbraucht (Langzeit-Verhalten).
- `CraftInventory`/`CraftPlayer.giveExp` etc. haben keinen `AsyncCatcher`; async Inventar-Änderungen (z. B. aus
  `AsyncChatEvent`) racen mit Klicks → Verlust/Dupe möglich. Plugin-Disziplin nötig.
- `CraftFurnace`-Snapshot enthält `recipesUsed`; ein Rollback-Plugin, das `update(true)` nach Entnahme aufruft, stellt
  die XP wieder her.
- Chunk-Save-Fehler behalten die ältere Kopie auf der Platte (Container-Rollback bei separat gespeichertem
  Spieler-Inventar) – kein spielerseitiger Trigger gefunden.

---

## 5. Noch offene / nicht gefixte Punkte
- 2.5 Velocity-Replay (Protokolländerung nötig). Zusätzlich: `velocityLoginMessageId` wird nach erfolgreichem Forward
  nicht zurückgesetzt – eine zweite gültige Antwort würde das Profil-Setup erneut durchlaufen (spekulativ).
- 3.0a Adventure-Chat-`ClickCallback`s an Empfänger binden (API-/Encoder-Änderung; als Option vorgemerkt) und
  Dialog-Antworten gegen die Input-Definitionen validieren.
- Unbegrenzte Config-Phase-Verbindungen (zählen nicht gegen `max-players`, kein Timeout außer Keepalive) – ein
  Config-Deadline wäre sinnvoll.
- Resource-Pack-Status kann für nie gesendete Pack-UUIDs gefälscht werden (`Player#getResourcePackStatus`).
- `bypassSelectorPermissions` ist ein mutables Feld auf einem ggf. geteilten `CommandSourceStack` (kleines Race-Fenster
  bei async Nutzung von `resolveWithContext`).
- Dimension-Keys als Ordnerpfade: **geprüft, sicher** – `Identifier.resolveAgainst` normalisiert und erzwingt den Root.

## 6. Übersicht der geänderten Dateien
Paper-Code (`paper-api`, `paper-server/src/main`): `OversizedItemComponentSanitizer`, `PaperPermissionManager`,
`PermissibleBase`, `MavenLibraryResolver`, `PaperCommand`, `DumpListenersCommand`, `PluginDescriptionFile`,
`PluginConfigConstraints`, `DefaultPermissions`, `ClickCallbackProviderImpl`, `DialogCallbackCollector` (neu),
`ReadablePlayerCookieConnectionImpl`, `CraftExperienceOrb`, `CraftInventory`, `CraftInventoryCustom`.

Vanilla-Patches (`paper-server/patches/sources`): `LegacyQueryHandler`, `RconThread`, `RconClient`, `StoredUserList`,
`UserBanListEntry`, `ServerLoginPacketListenerImpl`, `ServerHandshakePacketListenerImpl`, `ServerConnectionListener`,
`ByteBufCodecs`, `ServerboundCustomQueryAnswerPacket`, `CommandSourceStack`, `BaseCommandBlock`,
`ServerCommonPacketListenerImpl`, `ServerGamePacketListenerImpl`, `ServerConfigurationPacketListenerImpl`,
`LecternMenu`, `AbstractContainerMenu`, `MerchantResultSlot`, `HopperBlockEntity`, `ExperienceOrb`, `ItemStack`,
`PlayerAdvancements`, `DispenseItemBehavior`.
