#!/usr/bin/env python3
"""
ChameleonUltra Tag Simulator
=============================
Simuliert ein RFID-Tag für eine bestimmte Dauer, um Reader zu testen.

Unterstützte Tag-Typen:
  mf1k      Mifare Classic 1K  (4- oder 7-Byte UID, HF 13.56 MHz)
  mf4k      Mifare Classic 4K  (4- oder 7-Byte UID, HF 13.56 MHz)
  mfmini    Mifare Mini        (4- oder 7-Byte UID, HF 13.56 MHz)
  ntag213   NTAG 213           (7-Byte UID, HF 13.56 MHz)
  ntag215   NTAG 215           (7-Byte UID, HF 13.56 MHz)
  ntag216   NTAG 216           (7-Byte UID, HF 13.56 MHz)
  em410x    EM410x             (5-Byte ID,  LF 125 kHz)

Beispiele:
  python tag_simulator.py --type mf1k --id DEADBEEF --duration 30
  python tag_simulator.py --type em410x --id AABBCCDDEE --duration 60
  python tag_simulator.py --type ntag213 --id 04A1B2C3D4E5F6 --duration 10 --slot 2
  python tag_simulator.py --type mf1k --id DEADBEEF --duration 0   # läuft bis Strg+C
  python tag_simulator.py --port COM3 --type mf1k --id 11223344 --duration 30
  python tag_simulator.py --type mf1k --id DEADBEEF --duration 30 --reset  # NFCT_RESET am Ende (kein Neustart, USB bleibt)
"""

import struct
import sys
import time
import signal
import argparse
from pathlib import Path

# Sicherstellen, dass die Chameleon-Module gefunden werden
sys.path.insert(0, str(Path(__file__).parent))

try:
    from chameleon_com import ChameleonCom, OpenFailException
    from chameleon_cmd import ChameleonCMD
    from chameleon_enum import Command, SlotNumber, Status, TagSpecificType, TagSenseType
except ImportError as e:
    print(f"Fehler: Chameleon-Module nicht gefunden – {e}")
    print("Stelle sicher, dass dieses Skript im Verzeichnis software/script liegt.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Konfiguration der unterstützten Tag-Typen
# ---------------------------------------------------------------------------

TAG_CONFIGS = {
    "mf1k": {
        "name": "Mifare Classic 1K",
        "type": TagSpecificType.MIFARE_1024,
        "sense": TagSenseType.HF,
        "uid_lengths": [4, 7],
    },
    "mf4k": {
        "name": "Mifare Classic 4K",
        "type": TagSpecificType.MIFARE_4096,
        "sense": TagSenseType.HF,
        "uid_lengths": [4, 7],
    },
    "mfmini": {
        "name": "Mifare Mini",
        "type": TagSpecificType.MIFARE_Mini,
        "sense": TagSenseType.HF,
        "uid_lengths": [4, 7],
    },
    "ntag213": {
        "name": "NTAG 213",
        "type": TagSpecificType.NTAG_213,
        "sense": TagSenseType.HF,
        "uid_lengths": [7],
    },
    "ntag215": {
        "name": "NTAG 215",
        "type": TagSpecificType.NTAG_215,
        "sense": TagSenseType.HF,
        "uid_lengths": [7],
    },
    "ntag216": {
        "name": "NTAG 216",
        "type": TagSpecificType.NTAG_216,
        "sense": TagSenseType.HF,
        "uid_lengths": [7],
    },
    "em410x": {
        "name": "EM410x (125 kHz LF)",
        "type": TagSpecificType.EM410X,
        "sense": TagSenseType.LF,
        "uid_lengths": [5],
    },
}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def parse_hex_id(hex_str: str, expected_lengths: list[int]) -> bytes:
    """Parst eine Hex-Zeichenkette und prüft die erwartete Länge."""
    hex_str = hex_str.replace(":", "").replace(" ", "").upper()
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Ungültige Hex-Länge: '{hex_str}' (ungerade Anzahl Zeichen)")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError(f"Ungültige Hex-Zeichen in: '{hex_str}'")
    if len(data) not in expected_lengths:
        lengths_str = " oder ".join(f"{n} Byte(s)" for n in expected_lengths)
        raise ValueError(
            f"ID-Länge {len(data)} Byte(s) nicht gültig für diesen Tag-Typ. "
            f"Erwartet: {lengths_str}."
        )
    return data


def auto_detect_port() -> str | None:
    """Versucht den ChameleonUltra-Port automatisch zu erkennen."""
    import serial.tools.list_ports
    for port in serial.tools.list_ports.comports():
        if port.vid == 0x6868 and port.pid == 0x8686:
            return port.device
    return None


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f} Sekunde(n)"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} Minute(n)"
    else:
        return f"{seconds / 3600:.1f} Stunde(n)"


def print_status(msg: str, ok: bool = True):
    marker = "[OK]" if ok else "[!!]"
    print(f"  {marker} {msg}")


# ---------------------------------------------------------------------------
# Hauptlogik
# ---------------------------------------------------------------------------

class TagSimulator:
    def __init__(self, port: str, slot: SlotNumber):
        self.port = port
        self.slot = slot
        self.device = ChameleonCom()
        self.cmd: ChameleonCMD | None = None
        self._was_reader_mode: bool = False
        self._was_active_slot: SlotNumber = SlotNumber.SLOT_1
        self._active = False

    def connect(self):
        print(f"\nVerbinde mit {self.port} ...")
        self.device.open(self.port)
        self.cmd = ChameleonCMD(self.device)
        self._was_reader_mode = self.cmd.is_device_reader_mode()
        self._was_active_slot = SlotNumber.from_fw(self.cmd.get_active_slot())
        print_status(f"Verbunden (Gerät war im {'Reader'if self._was_reader_mode else 'Emulator'}-Modus)")

    def disconnect(self):
        if self.device:
            try:
                self.device.close()
            except Exception:
                pass

    def setup_hf_tag(self, cfg: dict, uid: bytes):
        """Konfiguriert einen HF-Tag (Mifare / NTAG)."""
        # Alle Konfiguration und FDS-Schreibvorgänge werden im Reader-Modus
        # (NFCT aus) durchgeführt. Erst ganz am Ende wird auf Emulator-Modus
        # gewechselt. So können Flash-Interrupts (FDS GC) das NFCT-Timing
        # nicht stören → keine intermittierenden Erkennungsfehler.
        self.cmd.set_device_reader_mode(True)
        time.sleep(0.3)

        self.cmd.set_active_slot(self.slot)
        self.cmd.set_slot_tag_type(self.slot, cfg["type"])
        try:
            # 15s Timeout statt Standard-3s: FDS-Schreibvorgänge (inkl. GC) können
            # bei vollem Flash deutlich länger als 3s dauern. Ein vorzeitiger Python-Timeout
            # während der Gerät noch schreibt führt dazu, dass nachfolgende Befehle auf ein
            # blockiertes Gerät treffen → Slot-Konfiguration inkonsistent → Tag nicht erkannt.
            slot_data = struct.pack('!BH', SlotNumber.to_fw(self.slot), int(cfg["type"]))
            resp = self.cmd.device.send_cmd_sync(
                Command.SET_SLOT_DATA_DEFAULT, slot_data, timeout=15
            )
            if resp.status == Status.NOT_IMPLEMENTED:
                print_status("Blockdaten-Reset übersprungen (FDS voll) – vorhandene Daten bleiben", ok=False)
            elif resp.status != Status.SUCCESS:
                print_status(f"Blockdaten-Reset Fehler: status=0x{resp.status:02x}", ok=False)
        except TimeoutError:
            print_status("Blockdaten-Reset Timeout nach 15s – Gerät möglicherweise blockiert", ok=False)
        except Exception as e:
            print_status(f"Blockdaten-Reset übersprungen ({e}) – vorhandene Daten bleiben", ok=False)
        self.cmd.set_slot_enable(self.slot, TagSenseType.HF, True)
        # LF für diesen Slot deaktivieren: verhindert Dual-Frequency-Modus (LED rot).
        # Dual-Frequency bedeutet HF+LF-Sensing gleichzeitig → mehr CPU-Last →
        # höhere Wahrscheinlichkeit, das HF-Timing-Fenster (Mifare Auth ≤600 µs) zu verpassen.
        # Sicher, weil HF gerade aktiviert wurde → is_slot_enabled(HF)=true →
        # der automatische Slot-Wechsel in cmd_processor_set_slot_enable wird NICHT ausgelöst.
        self.cmd.set_slot_enable(self.slot, TagSenseType.LF, False)

        # Anti-Coll-Daten setzen und speichern – noch im Reader-Modus (NFCT aus).
        # slot_data_config_save() löst einen FDS-Schreibvorgang aus; dieser darf
        # nicht gleichzeitig mit aktivem NFCT laufen, da Flash-Interrupts das
        # 600-µs-Mifare-Auth-Timing-Fenster unterbrechen können.
        ac = self.cmd.hf14a_get_anti_coll_data()
        atqa = bytes(ac["atqa"])
        sak  = bytes(ac["sak"])
        self.cmd.hf14a_set_anti_coll_data(uid=uid, atqa=atqa, sak=sak, ats=b"")
        self.cmd.slot_data_config_save()

        rb = self.cmd.hf14a_get_anti_coll_data()
        actual = bytes(rb["uid"]).hex().upper()
        if actual == uid.hex().upper():
            print_status(
                f"Verifiziert – UID={actual}  "
                f"ATQA={bytes(rb['atqa']).hex().upper()}  "
                f"SAK={bytes(rb['sak']).hex().upper()}"
            )
        else:
            print_status(f"UID-Mismatch! Erwartet {uid.hex().upper()}, Gerät={actual}", ok=False)

        # Erst jetzt in Emulator-Modus wechseln: tag_mode_enter() läuft vollständig
        # (da wir aus Reader-Modus kommen) → ruft tag_emulation_sense_run() →
        # NFC-Sensing wird für den jetzt aktivierten Slot eingeschaltet.
        # Längere Pause damit der NFCT-Peripheral vollständig initialisiert ist,
        # bevor der Reader anfängt zu pollen.
        self.cmd.set_device_reader_mode(False)
        time.sleep(0.5)

    def setup_lf_tag(self, cfg: dict, uid: bytes):
        """Konfiguriert einen LF-Tag (EM410x)."""
        self.cmd.set_device_reader_mode(True)
        time.sleep(0.3)

        self.cmd.set_active_slot(self.slot)
        self.cmd.set_slot_tag_type(self.slot, cfg["type"])
        self.cmd.em410x_set_emu_id(uid)
        self.cmd.set_slot_enable(self.slot, TagSenseType.LF, True)

        self.cmd.set_device_reader_mode(False)
        time.sleep(0.3)

        self.cmd.slot_data_config_save()
        print_status(f"ID={uid.hex().upper()}  Slot {self.slot.value} → {cfg['name']}")

    def restore(self, sense: TagSenseType):
        """Deaktiviert den simulierten Slot und stellt den Gerätezustand wieder her."""
        if self.cmd is None:
            return
        try:
            # Reader-Modus ZUERST: reader_mode_enter() → tag_emulation_sense_end() → NFC-Hardware sofort aus.
            # Danach: set_slot_enable(..., False) triggert in der Firmware change_slot_auto() →
            # tag_emulation_change_slot(slot_neu, sense_disable = (mode != READER)).
            # Da wir jetzt im Reader-Modus sind, ist sense_disable=false →
            # tag_emulation_sense_run() wird NICHT aufgerufen → Slot 2 emuliert nicht.
            self.cmd.set_device_reader_mode(True)
            time.sleep(0.2)

            # Slot deaktivieren (auto-Slot-Wechsel passiert, aber NFC bleibt aus).
            self.cmd.set_slot_enable(self.slot, sense, False)

            # Originalen aktiven Slot wiederherstellen: verhindert, dass der
            # auto-Slot-Wechsel den falschen Slot beim nächsten Emulator-Start aktiviert.
            self.cmd.set_active_slot(self._was_active_slot)

            self.cmd.slot_data_config_save()
            print_status(f"Slot {self.slot.value} deaktiviert und in Flash gespeichert")

            if not self._was_reader_mode:
                # Zurück in Emulator-Modus: tag_mode_enter() → sense_run() mit
                # _was_active_slot (= ursprünglicher Slot, jetzt deaktiviert) → kein NFC.
                self.cmd.set_device_reader_mode(False)
                print_status("Emulator-Modus wiederhergestellt")
            else:
                print_status("Reader-Modus beibehalten")
        except Exception as e:
            print_status(f"Warnung beim Wiederherstellen: {e}", ok=False)

    def device_reset(self):
        """MCU-Neustart via SOFT_RESET (Cmd 1022, kein FDS-Wipe).
        Setzt den NFCT-Peripheral vollständig zurück. Vor dem Reset wird
        GPREGRET Bit 6 gesetzt → Gerät bootet direkt in Reader-Modus →
        keine Emulation nach dem Neustart, kein Reconnect nötig."""
        if self.cmd is None:
            return
        try:
            # SOFT_RESET (Cmd 1022): setzt GPREGRET Bit 6, dann delayed_reset(50ms).
            # Firmware liest GPREGRET beim Boot → Reader-Modus → keine Emulation.
            self.cmd.device.send_cmd_sync(Command.SOFT_RESET, timeout=5)
            print_status("Gerät wird neugestartet (NFCT-Reset, bootet in Reader-Modus)")
        except Exception:
            pass
        # Verbindung schliessen bevor der Port durch den MCU-Neustart wegbricht
        # (setzt event_closing → unterdrückt "Serial Error"-Meldung).
        self.device.close()
        time.sleep(1.0)  # Auf Neustart warten

    def wait(self, duration: float):
        """Wartet für die angegebene Dauer mit Fortschrittsanzeige."""
        self._active = True
        if duration <= 0:
            print("\n  Tag ist aktiv. Drücke Strg+C zum Beenden.\n")
            while self._active:
                time.sleep(0.5)
        else:
            print(f"\n  Tag ist aktiv für {format_duration(duration)}. Drücke Strg+C zum vorzeitigen Beenden.\n")
            end_time = time.monotonic() + duration
            while self._active:
                remaining = end_time - time.monotonic()
                if remaining <= 0:
                    break
                bar_total = 40
                elapsed = duration - remaining
                filled = int(bar_total * elapsed / duration)
                bar = "=" * filled + "-" * (bar_total - filled)
                print(
                    f"\r  [{bar}] {remaining:6.1f}s verbleibend  ",
                    end="",
                    flush=True,
                )
                time.sleep(0.2)
            print(f"\r  [{'=' * 40}]   0.0s verbleibend  ")

    def stop(self):
        self._active = False


# ---------------------------------------------------------------------------
# Argument-Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ChameleonUltra Tag Simulator – simuliert ein RFID-Tag für einen Reader-Test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--port", "-p",
        metavar="PORT",
        help="Serieller Port (z.B. COM3, /dev/ttyACM0). Wird automatisch erkannt, falls nicht angegeben.",
    )
    parser.add_argument(
        "--type", "-t",
        metavar="TYP",
        required=True,
        choices=TAG_CONFIGS.keys(),
        help=f"Tag-Typ: {', '.join(TAG_CONFIGS.keys())}",
    )
    parser.add_argument(
        "--id", "-i",
        metavar="HEX",
        required=True,
        help=(
            "Tag-ID als Hex-Zeichenkette (ohne 0x-Präfix). "
            "mf1k/mf4k/mfmini: 4 oder 7 Byte | ntag*: 7 Byte | em410x: 5 Byte. "
            "Beispiel: DEADBEEF oder AABBCCDDEE"
        ),
    )
    parser.add_argument(
        "--duration", "-d",
        metavar="SEKUNDEN",
        type=float,
        default=30,
        help="Aktive Dauer in Sekunden (0 = unbegrenzt bis Strg+C, Standard: 30).",
    )
    parser.add_argument(
        "--slot", "-s",
        metavar="SLOT",
        type=int,
        default=1,
        choices=range(1, 9),
        help="Geräte-Slot (1–8, Standard: 1).",
    )
    parser.add_argument(
        "--reset", "-r",
        action="store_true",
        default=False,
        help=(
            "NFCT-Peripheral nach der Simulation zurücksetzen (Cmd 1039, kein MCU-Neustart). "
            "Behebt das kumulative NFCT-Bug-Problem nach ~3 Runs. "
            "USB bleibt verbunden, FDS-Daten bleiben erhalten. "
            "Erfordert Firmware mit NFCT_RESET-Befehl."
        ),
    )
    return parser


# ---------------------------------------------------------------------------
# Einstiegspunkt
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    cfg = TAG_CONFIGS[args.type]

    # Tag-ID validieren
    try:
        uid = parse_hex_id(args.id, cfg["uid_lengths"])
    except ValueError as e:
        parser.error(str(e))
        return

    # Slot-Nummer konvertieren
    try:
        slot = SlotNumber(args.slot)
    except ValueError:
        parser.error(f"Ungültiger Slot: {args.slot}. Erlaubt: 1–8.")
        return

    # Port ermitteln
    port = args.port
    if port is None:
        port = auto_detect_port()
        if port is None:
            print(
                "Fehler: ChameleonUltra nicht gefunden. "
                "Bitte --port angeben oder Gerät per USB verbinden."
            )
            sys.exit(1)
        print(f"Gerät automatisch erkannt: {port}")

    # Zusammenfassung ausgeben
    print("\n" + "=" * 55)
    print("  ChameleonUltra Tag Simulator")
    print("=" * 55)
    print(f"  Tag-Typ  : {cfg['name']}")
    print(f"  Tag-ID   : {uid.hex().upper()}")
    print(f"  Slot     : {args.slot}")
    dur_str = format_duration(args.duration) if args.duration > 0 else "unbegrenzt (Strg+C)"
    print(f"  Dauer    : {dur_str}")
    print(f"  Port     : {port}")
    print(f"  Reset    : {'ja (NFCT_RESET, USB bleibt)' if args.reset else 'nein'}")
    print("=" * 55)

    sim = TagSimulator(port=port, slot=slot)

    # Signal-Handler für sauberes Beenden
    def on_interrupt(sig, frame):
        print("\n\n  Unterbrochen – beende Simulation ...")
        sim.stop()

    signal.signal(signal.SIGINT, on_interrupt)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, on_interrupt)

    try:
        sim.connect()

        print("\nKonfiguriere Tag ...")
        if cfg["sense"] == TagSenseType.HF:
            sim.setup_hf_tag(cfg, uid)
        else:
            sim.setup_lf_tag(cfg, uid)

        # USB-Polling pausieren: thread_data_receive blockiert nun für die gesamte
        # Simulationsdauer in einem einzigen read() statt 10x/Sekunde USB-Interrupts
        # auf dem nRF52840 auszulösen. Sobald restore()-Antworten eintreffen,
        # kehrt read() sofort zurück (Daten vorhanden → kein Warten nötig).
        wait_timeout = (args.duration + 30) if args.duration > 0 else 3600
        try:
            sim.device.transport.timeout = wait_timeout
        except Exception:
            pass

        print("\nSimulation läuft ...")
        sim.wait(args.duration)

    except Exception as e:
        print(f"\nFehler: {e}")
    finally:
        # Normalen Timeout wiederherstellen damit restore()-Kommandos schnell
        # verarbeitet werden können.
        try:
            sim.device.transport.timeout = 0.1
        except Exception:
            pass

        print("\nStelle Gerätezustand wieder her ...")
        sim.restore(cfg["sense"])
        if args.reset:
            print("\nStarte Gerät neu (NFCT-Reset) ...")
            sim.device_reset()
        sim.disconnect()
        print("\nSimulation beendet.")


if __name__ == "__main__":
    main()
