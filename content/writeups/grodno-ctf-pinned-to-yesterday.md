---
title: "CTF Write-up: Pinned to Yesterday"
date: "2026.07.21"
author: "admin"
categoryEn: "FORENSICS"
categoryJp: "鑑識"
difficulty: "mid"
---
+++
title = 'Pinned to Yesterday — Write-up'
date = '2026-07-13T23:56:25+07:00'
draft = false
tags = ['GrodnoCTF', 'windows', 'registry', 'prefetch', 'shellbags']
categories = ['Forensics']
+++

# CTF Write-up: Pinned to Yesterday

**Category:** Windows Forensics
**Flag format:** `grodno{pdf_folder_exe}`
**Flag cuối:** `grodno{WhatsNew.2898.pdf_ShellBagsExplorer_CALC.EXE}`

---

## Mô tả bài

> You have a set of Windows artifacts from an analyst workstation.
> Recover three values:
> - The PDF filename that is **first** in `RecentDocs\.pdf`
> - The **working folder name** from `TypedPaths` associated with ShellBagsExplorer
> - The **executable filename** from the sample Prefetch
>
> Flag: `grodno{pdf_folder_exe}`
> Example: `grodno{doc.pdf_tools_notepad.exe}`

**Tải về đề bài:** [challenge files — OneDrive](https://1drv.ms/u/c/2f661437c52d8a10/IQD4O2TDL68jQ7ZERm40wy5WAQWUQ4UEwJPBbX9FTjEA79Y?e=If7Phn)

---

## Nhận file và kiểm tra nhanh

Mở file zip ra, bên trong có hai thư mục:

```
Registry.Test/
    Hives/
        NTUSER.DAT        ← file quan trọng nhất
        SOFTWARE
        SYSTEM
        SAM
        ... (nhiều hive khác)
JumpList.Test/
    TestFiles/
        Bad/
            CALC.EXE-3FBEF7FD.pf   ← chú ý file này!
        Win7/
        Win81/
        Win10/
```

Nhìn qua, bài yêu cầu ba thứ: **một file PDF**, **một tên thư mục**, và **một file thực thi**. Ba nguồn dữ liệu tương ứng là: Registry `NTUSER.DAT` (cho PDF và folder), và file `.pf` Prefetch (cho exe). Bắt đầu thôi.

---

## Phần 1: File thực thi từ Prefetch

### Phát hiện vấn đề

Nhìn vào file `CALC.EXE-3FBEF7FD.pf` trong thư mục `Bad/`, câu hỏi đầu tiên xuất hiện trong đầu: tại sao lại nằm trong thư mục tên là **"Bad"**? Thử đọc hex dump ngay:

```bash
$ xxd JumpList.Test/TestFiles/Bad/CALC.EXE-3FBEF7FD.pf | head -n 4
00000000: 4d41 4d04 e8ba 0000 a5b7 a6c8 baa8 aaa8  MAM............
00000010: aaa7 aaa8 abb7 aaa8 aac7 aab8 bab7 aab8  ................
```

Chú ý ngay **4 byte đầu**: `4d 41 4d 04` → đây là magic header `MAM\x04`. Đây không phải là Prefetch Windows 7/8 thông thường (magic `SCCA`) mà là **Prefetch Windows 10 được nén bằng thuật toán Xpress Huffman**. "Bad" ở đây có nghĩa là các tool cũ sẽ "bị hỏng" (fail) khi đọc file này vì chúng không hỗ trợ giải nén MAM.

Thử dùng `strings` — không có gì đọc được:

```bash
$ strings JumpList.Test/TestFiles/Bad/CALC.EXE-3FBEF7FD.pf
6'#4q
m`K6B...   ← toàn garbage
```

Phải giải nén trước mới đọc được.

### Giải nén MAM bằng Python

Cấu trúc của file MAM Prefetch rất đơn giản:
- Bytes `0-3`: Magic `MAM\x04`
- Bytes `4-7`: Kích thước dữ liệu sau khi giải nén (little-endian uint32)
- Bytes `8-end`: Dữ liệu nén theo chuẩn Xpress Huffman

Cài thư viện `dissect.util` vào virtualenv rồi viết script giải nén:

```bash
$ python3 -m venv venv
$ ./venv/bin/pip install dissect.util
```

```python
import struct
from dissect.util.compression.lzxpress_huffman import decompress

with open('JumpList.Test/TestFiles/Bad/CALC.EXE-3FBEF7FD.pf', 'rb') as f:
    raw = f.read()

# Kiểm tra magic
assert raw[:4] == b'MAM\x04', "Không phải MAM format!"

# Lấy kích thước dữ liệu gốc
uncompressed_size = struct.unpack_from('<I', raw, 4)[0]
print(f'Uncompressed size: {uncompressed_size} bytes')  # 47848

# Giải nén
uncompressed = decompress(raw[8:])
print(f'Decompressed: {len(uncompressed)} bytes')

# Dump 128 byte đầu để kiểm tra cấu trúc
for i in range(0, 128, 16):
    hex_part = ' '.join(f'{b:02x}' for b in uncompressed[i:i+16])
    print(f'{i:04x}: {hex_part}')
```

Output:

```
Uncompressed size: 47848 bytes
Decompressed: 47848 bytes

=== First 128 bytes (hex) ===
0000: 1e 00 00 00 53 43 43 41 11 00 00 00 e8 ba 00 00
0010: 43 00 41 00 4c 00 43 00 2e 00 45 00 58 00 45 00
0020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Sau khi giải nén, ta thấy rõ:
- Bytes `0-3`: `1e 00 00 00` → Version 30 (Windows 10 Prefetch format)
- Bytes `4-7`: `53 43 43 41` → `SCCA` magic (signature thật của Prefetch)
- **Bytes `0x10` trở đi**: `43 00 41 00 4c 00 43 00 2e 00 45 00 58 00 45 00` → Đây là chuỗi UTF-16LE của tên file thực thi

Giải mã UTF-16LE:

```python
exe_name = uncompressed[0x10:0x10+60].decode('utf-16le').rstrip('\x00')
print(exe_name)  # CALC.EXE
```

✅ **Kết quả:** `CALC.EXE`

---

## Phần 2: Tên thư mục từ TypedPaths

### Đọc Registry trên Linux bằng reglookup

Không có Registry Editor trên Linux, nhưng ta có `reglookup`. Key cần tìm là:

`Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`

Đây là nơi Windows ghi lại **tất cả các đường dẫn mà người dùng đã gõ trực tiếp** vào thanh địa chỉ của Windows Explorer.

```bash
$ reglookup "Registry.Test/Hives/NTUSER.DAT" 2>/dev/null | grep "TypedPaths/url"
```

Output:

```
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url1,SZ,D:\,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url2,SZ,ftp://ftp.es.kde.org/,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url3,SZ,ftp://ftp.arxsys.fr/,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url4,SZ,ftp://ftp.freshrpms.net/,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url5,SZ,ftp://ftp.swfwmd.state.fl.us/pub/,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url6,SZ,Y:\,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url7,SZ,C:\ProjectWorkingFolder\ShellBagsExplorer,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url8,SZ,C:\,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url9,SZ,This PC,
/Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths/url10,SZ,C:\ProjectWorkingFolder\Hasher\trunk\Hasher\bin,
...
```

Thấy ngay `url7`: `C:\ProjectWorkingFolder\ShellBagsExplorer`.

### Phân tích: "working folder" là gì?

Đây là lúc phải suy nghĩ. Toàn bộ đường dẫn là `C:\ProjectWorkingFolder\ShellBagsExplorer`. Đề bài hỏi **"working folder name associated with ShellBagsExplorer"**. Tức là "thư mục làm việc" liên kết trực tiếp với công cụ ShellBagsExplorer — đó chính là **thư mục chứa nó**, cũng là **thư mục mà người dùng đã điều hướng đến khi làm việc với tool này**.

Nhìn cấu trúc đường dẫn: `C:\ProjectWorkingFolder\ShellBagsExplorer`
- `C:\ProjectWorkingFolder` = thư mục gốc của toàn bộ dự án
- `ShellBagsExplorer` = tên thư mục cụ thể, chính xác là nơi làm việc với công cụ đó

"Working folder" (thư mục làm việc) là chính `ShellBagsExplorer` — không phải thư mục cha.

✅ **Kết quả:** `ShellBagsExplorer`

---

## Phần 3: File PDF "đầu tiên" trong RecentDocs — Cái bẫy chính của bài

Đây là phần tốn thời gian nhất, và cũng là nơi bài học quan trọng nhất nằm ở đây.

### Đọc dữ liệu thô từ Registry

```bash
$ reglookup "Registry.Test/Hives/NTUSER.DAT" 2>/dev/null | grep "RecentDocs/\.pdf" | grep ",BINARY,"
```

Kết quả cho thấy 11 dòng, trong đó có 1 dòng `MRUListEx` và 10 dòng giá trị đánh số từ 0 đến 9. Danh sách đầy đủ các file PDF trong Registry:

| Value | Tên file |
|-------|----------|
| 0 | `ShellBagsExplorerManual.pdf` |
| 1 | `OJYBIB.pdf` |
| 2 | `invoice_4-141025-5909.pdf` |
| 3 | `invoice_4-140825-6359.pdf` |
| 4 | `osTriageManual.pdf` |
| 5 | `INV00818612.pdf` |
| 6 | `GOON2Manual.pdf` |
| 7 | `CAT_Deployment_in_Support_of_OPWAN_Roll-out.pdf` |
| 8 | `WhatsNew.2898.pdf` |
| 9 | `QuickStartGuide_SanDiskSecureAccessV2.0.pdf` |

Và chuỗi `MRUListEx` (dạng hex URL-encoded) decode ra thành mảng số nguyên 32-bit little-endian:

```
01 00 00 00  →  1
00 00 00 00  →  0
07 00 00 00  →  7
04 00 00 00  →  4
02 00 00 00  →  2
03 00 00 00  →  3
05 00 00 00  →  5
06 00 00 00  →  6
09 00 00 00  →  9
08 00 00 00  →  8
FF FF FF FF  →  terminator
```

### Sai lầm #1: Tin vào thứ tự Value Name

Nhìn thấy 10 entries từ `0` đến `9`, phản xạ đầu tiên là: "Value `0` thì đương nhiên là đầu tiên rồi." Value `0` trỏ đến `ShellBagsExplorerManual.pdf`. Thêm vào đó, câu hỏi 2 cũng có liên quan đến ShellBagsExplorer, nên logic có vẻ "gọn". Nộp thử → **Sai.**

### Sai lầm #2: Hiểu "first" là "Most Recently Used"

Cơ chế MRU (Most Recently Used) trong Windows hoạt động như sau: **mỗi khi người dùng mở một file, Windows đẩy file đó lên đầu danh sách MRUListEx**. Vị trí đầu tiên trong mảng = file được mở **gần đây nhất**.

Phân tích mảng `[1, 0, 7, 4, 2, 3, 5, 6, 9, 8]`:
- Vị trí đầu = Value `1` = `OJYBIB.pdf` → file được mở **gần đây nhất**

Trong Forensics, "first in MRU" thường đồng nghĩa với "most recently used". Nộp `OJYBIB.pdf` → **Vẫn Sai.**

### Khoảnh khắc nhận ra: Tiêu đề bài là hint

Sau khi thử đủ mọi cách đọc dữ liệu kỹ thuật và đều thất bại, câu hỏi quan trọng xuất hiện:

> *"Người ra đề không bao giờ đặt câu trả lời ở chỗ đầu tiên ai cũng nhìn thấy. Tiêu đề bài là **'Pinned to Yesterday'** — từ 'Yesterday' (Ngày hôm qua) ám chỉ điều gì đó **trong quá khứ xa nhất**, không phải gần đây nhất."*

Nhìn lại `MRUListEx` theo đúng logic thời gian:

```
Mảng MRU: [1, 0, 7, 4, 2, 3, 5, 6, 9, 8]
           ^--- MỚI NHẤT               ^--- CŨ NHẤT
```

Windows đẩy file vào **đầu** mỗi khi mở. Vậy nên:
- **File ở cuối mảng** = file được thêm vào **đầu tiên nhất** = file được mở **sớm nhất** trong lịch sử, "từ ngày hôm qua".

Vị trí cuối cùng là Value `8` = **`WhatsNew.2898.pdf`**.

Kiểm tra lại bằng code Python để chắc chắn:

```python
import struct

mru_bytes = bytes.fromhex(
    '01000000'
    '00000000'
    '07000000'
    '04000000'
    '02000000'
    '03000000'
    '05000000'
    '06000000'
    '09000000'
    '08000000'
    'FFFFFFFF'
)

order = []
for i in range(0, len(mru_bytes) - 4, 4):
    val = struct.unpack_from('<I', mru_bytes, i)[0]
    if val == 0xFFFFFFFF:
        break
    order.append(val)

print('Thứ tự MRU (mới → cũ):', order)
print(f'File cũ nhất = Value {order[-1]} = WhatsNew.2898.pdf')
```

Output:
```
Thứ tự MRU (mới → cũ): [1, 0, 7, 4, 2, 3, 5, 6, 9, 8]
File cũ nhất = Value 8 = WhatsNew.2898.pdf
```

✅ **Kết quả:** `WhatsNew.2898.pdf`

---

## Ghép Flag

| Thành phần | Giá trị | Nguồn |
|---|---|---|
| PDF đầu tiên (cũ nhất) | `WhatsNew.2898.pdf` | `NTUSER.DAT` → `RecentDocs\.pdf` → MRUListEx cuối |
| Working folder | `ShellBagsExplorer` | `NTUSER.DAT` → `TypedPaths` → url7 |
| Executable | `CALC.EXE` | `CALC.EXE-3FBEF7FD.pf` → giải nén MAM → offset 0x10 |

```
grodno{WhatsNew.2898.pdf_ShellBagsExplorer_CALC.EXE}
```

---

## Bài học rút ra

**1. Đọc tiêu đề bài thật kỹ — đó thường là hint lớn nhất.**
"Pinned to Yesterday" không phải tên ngẫu nhiên. Từ "Yesterday" chỉ thẳng vào việc phải tìm artifact **cũ nhất**, không phải mới nhất. Nếu đọc kỹ từ đầu, có thể tiết kiệm được rất nhiều thời gian.

**2. Hiểu sai cơ chế MRUListEx là bẫy phổ biến.**
MRUListEx không lưu theo thứ tự đánh số Value Name (`0`, `1`, `2`...). Nó lưu theo **thứ tự thời gian truy cập**, mới nhất ở đầu mảng, cũ nhất ở cuối. "First in list" ≠ "oldest file". Phải đọc mảng bytes để biết đúng thứ tự.

**3. Windows 10 Prefetch dùng nén MAM — `strings` sẽ không đọc được.**
File `.pf` có header `MAM\x04` phải giải nén bằng Xpress Huffman trước. Sau khi giải nén mới ra SCCA format chuẩn, và tên exe nằm tại offset `0x10` dưới dạng UTF-16LE.

**4. Trên Linux không có Registry Editor, nhưng `reglookup` làm được mọi thứ.**
Công cụ `reglookup` đọc trực tiếp file hive `.DAT` và trả về dạng CSV — hoàn toàn có thể dùng `grep` để lọc nhanh.
