# Tracking 1: OCEANMAP & STEELHOOK backdoors

On 28.12.2023, CERT-UA published an [article](https://cert.gov.ua/article/6276894) to warn about a new malware campaign counducted by APT28 (a.k.a Fancy Bear), using the backdoors OCEANMAP and STEELHOOK in order to
exfiltrate information from the victim. (here is the english traduction of the [article](https://medium.com/cyberscribers-exploring-cybersecurity/apt28-from-initial-damage-to-domain-controller-threats-in-an-hour-cert-ua-8399-1944dd6edcdf)).

- **OCEANMAP** is a malicious program developed using the C# programming language. The main functionality is to execute commands using cmd.exe. The IMAP protocol is used as a control channel. Commands, in base64-encoded form, are contained in the “Drafts” of the corresponding mailbox directories; each of the drafts contains the name of the computer, the user name and the OS version. The results of the commands are stored in the inbox directory. Implemented a configuration update mechanism (command validation interval, addresses, and authentication data of mail accounts), which involves patching the backdoor executable file and restarting the process. Persistence is ensured by creating . URL file ‘VMSearch.url’ in the startup directory.

I started my analysis afther seen this [photograph](./twitter-post.jpg) on twitter, showing a possible connection between the the DarkCasino attack and the APT28's one. In the end there was none, but something
hidden behind that ip was even more intresting (here is the complete [twitter post](https://twitter.com/BaoshengbinCumt/status/1762657919504732527)).

So I started digging around trying to find more informations. Firstly I found a [collection](https://www.virustotal.com/gui/collection/4fca51117f88d8172e0ea97d2d2878271a3135327edf248511b7e8d777a252d9) of IoCs on VirusTotal tied to the ip in the photograph: **194[.]126[.]178[.]8** . I started analyzing the files, trying to find *Client.py* that was also in the photo. Then I read more about this particular file from a comment of [Schmouni](https://www.virustotal.com/gui/user/Schmouni) on VirusTotal. This is the comment:

```txt
47f4b4d8f95a7e842691120c66309d5b 18f891a3737bb53cd1ab451e2140654a376a43b2d75f6695f3133d47a41952b6 Client.py (MASEPIE)
MASEPIE is a malicious program developed using the Python programming language. The main functionality is to download/upload files and execute commands.
The TCP protocol is used as a control channel. Data is encrypted using the AES-128-CBC algorithm; The key, which is a sequence of 16 arbitrary bytes, is generated at the beginning of the connection.
The persistence of the backdoor is ensured by the creation of the 'SysUpdate' key in the 'Run' branch of the OS registry, as well as, using the 'SystemUpdate.lnk' LNK file in the startup directory.
APT28: From Initial Damage to Domain Controller Threats in an Hour (CERT-UA#8399)
```

In the IoC contains three more files that are:

- 19d0c55ac466e4188c4370e204808ca0bc02bba480ec641da8190cb8aee92bdc.lnk
- VMSearch.exe
- KFP.311.152.2023.pdf.lnk
