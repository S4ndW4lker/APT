# INDUSTROYER 2

First seen in 2022, it's a malware that targets specifically ICS, with the aim to harm the critical infrastructure like power grids. It utilizes messages written in **IEC 60870-5-104 (IEC-104)** protocol to send *ON* or *OFF* commands. **IEC-104** is used for power system monitoring and control over TCP and is mainly implemented in Europe and the Middle East.

This malware variant, unlike [INDUSTROYER](https://cyberlaw.ccdcoe.org/wiki/Industroyer_%E2%80%93_Crash_Override_(2016)) used in 2016 to attack Ukraine’s national power company (Ukrenergo), allows actors to embed customized configurations that modify the malware’s behavior to specific intelligent electronic devices (IEDs) (e.g., protection relays, merging units, etc.) within the target environment.
