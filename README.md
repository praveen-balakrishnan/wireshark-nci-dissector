# Wireshark NFC Controller Interface dissector

A work-in-progress dissector plugin that can dissect NFC Controller Interface (NCI) messages between a Device Host and NFC Controller.

## Installation

To use this plugin, you must first [build Wireshark](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html).

Once you have obtained Wireshark's source code, add this plugin to `wireshark/plugins/epan/nci`. You can then create a `CMakeListsCustom.txt` in the Wireshark source directory, modifying `CMakeListsCustom.txt.example` from the source directory. Add `plugins/epan/nci` to `CUSTOM_PLUGIN_SRC_DIR` in your modified file. Then invoke CMake and build Wireshark.

As an example, in your Wireshark source code directory:

```
mkdir plugins/epan/nci
cp CMakeListsCustom.txt.example CMakeListsCustom.txt
vi CMakeListsCustom.txt
mkdir build
cd build
cmake ..
make
```

Once you have installed the plugin in Wireshark, go to `Preferences -> Protocols -> DLT_USER -> Encapsulations Table (Edit)`. Add `User 0 (DLT = 147)` as an entry and select `nci` as the payload dissector.

## Usage

This plugin is designed to work with `pcap` capture files.

To generate such a file from a data dump, you can use text2pcap for example.

```
text2pcap -l 147 dump.txt capture.pcap
```

Note: As NCI is not yet an [official link-layer header type](https://www.tcpdump.org/linktypes.html) for `pcap` capture files, this plugin instead uses the private `DLT_USER0 = 147` header type. If this causes a collision with your own usage of `DLT_USER0 - DLT_USER15`, you can change this easily by modifying the `NCI_DLT_USER` macro in `packet-nci.h`.
