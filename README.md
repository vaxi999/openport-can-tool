# OpenPort CAN Tool

A small native Windows application for sending and recording classic CAN frames through an installed OpenPort J2534 driver. Developed by Vasilije Doklestić for instrument-cluster bench experiments.

## Features

- Send a raw CAN frame once or repeatedly, with finite or continuous repetition.
- Validate and run sequences of up to 128 frames.
- Select 11-bit or 29-bit identifiers, configurable bitrate, and 0–8 payload bytes.
- Record RX/TX events to CSV and driver events to text logs.
- Filter or pause the display independently of recording.
- Stop transmission using Stop All or Escape; transmission stops on loss of focus by default.
- Includes an experimental steering-button profile from a specific VW bench setup. This profile is not universal.

## Requirements and use

Windows with an installed **x86 J2534 OpenPort driver**, including on 64-bit Windows. The driver is not distributed in this repository. Close other applications using the adapter before connecting.

Build the executable as described below, then run `OPENPORT_TEST_TABLE.exe`. Select the installed driver, the correct bitrate and identifier mode, and connect. Connecting alone does not send a test command. Enter a CAN identifier in hexadecimal and up to eight hexadecimal payload bytes, then choose single transmission or repetition.

Sequence syntax:

```text
CAN_ID#HEX_BYTES@DELAY_AFTER_FRAME_MS
```

`SEKVENCA.txt` contains a bench-specific steering-button example; review it before transmitting. Loading a sequence does not run it. The Serbian usage guide is [PROCITAJ.txt](PROCITAJ.txt).

## Scope

This is a **raw classic CAN tool**. It does not automatically implement ISO-TP, VW TP2.0, UDS/KWP sessions, or BAP/DDP packet assembly. CAN FD is not supported. Timing depends on Windows and the driver. A TX acceptance event means the driver accepted the frame, not that a module acted on it.

Use on a controlled bench with hardware you own or are authorized to test. Incorrect CAN traffic can affect connected modules. Stop ends this tool's transmission; it cannot undo actions already taken by a module.

## Build and verification

The supplied build runs on Linux with Python 3, GCC supporting `-m32` object compilation, and GNU binutils supporting `ld -m i386pe`. No Python or .NET runtime is required on the target Windows machine.

```sh
python3 build_windows.py
python3 verify_all.py
```

The build converts freestanding ELF32 objects to COFF, links a PE32 executable, and checks relocations, imports and ASLR structures. Tests exercise the parser, sender scheduling and frontend with mocked Win32/J2534 functions using AddressSanitizer and UndefinedBehaviorSanitizer.

**Verification limit:** these automated tests do not execute the actual Windows GUI, USB adapter or cluster. The source archive's documentation stated that this version had not yet been run on physical Windows/OpenPort hardware. Physical compatibility remains unverified here.

## Contributing

Bug reports and pull requests are welcome. Include Windows version, driver version, adapter model, bitrate, identifier mode and reproduction steps. Remove VINs, serial numbers and other private data from attached logs. Avoid attaching proprietary drivers or firmware.

## License

MIT. See [LICENSE](LICENSE). OpenPort and J2534 product names identify compatibility targets; this project is independent and is not endorsed by their vendors.
