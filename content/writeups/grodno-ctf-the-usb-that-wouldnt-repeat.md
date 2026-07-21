---
title: "CTF Write-up: The USB That Wouldn't Repeat"
date: "2026.07.21"
author: "admin"
categoryEn: "FORENSICS"
categoryJp: "鑑識"
difficulty: "mid"
---
+++
title = "The USB That Wouldn't Repeat — Write-up"
date = '2026-07-14T01:23:20+07:00'
draft = false
tags = ['GrodnoCTF', 'disk-imaging', 'ftk-imager', 'usb']
categories = ['Forensics']
+++

# CTF Write-up: The USB That Wouldn't Repeat

**Category:** Forensics / Disk Imaging
**Flag format:** `grodno{md5_first_md5_second}`
**Flag cuối:** `grodno{09817bced4213360c1cb2749aa375523_2bdab2c08b5b507876bf2f2d7e548cc5}`

---

## Mô tả bài

> We obtained an archive with USB acquisition artifacts and a short description of the experiment.
> Recover the MD5 hashes of the two Windows FTK Imager acquisitions:
> - Flash-firstrun.001
> - Flash-secondrun.001
>
> Flag format: `grodno{md5_first_md5_second}`

**Tải về đề bài:** [challenge files — OneDrive](https://1drv.ms/u/c/2f661437c52d8a10/IQDNhKqLrc7zSpg15bSfLgLcAcvfEFJKjWiAbRPcVUE3eDY?e=EM6nY2)

---

## Nhận file và kiểm tra nhanh

Giải nén file challenge ra thì thấy hai thứ:

```bash
$ ls -lh
```

```
total 99M
-rw-rw-r-- 1 poeency poeency  50M  'The USB That Wouldn't Repeat.zip'
-rw-r--r-- 1 poeency poeency  50M  usb-non-deterministic-files.zip
-rw-r--r-- 1 poeency poeency  66K  usb-non-deterministic-narrative.pdf
```

Một file PDF mô tả thí nghiệm và một file zip 50MB chứa artifacts. Cái tên bài — *"The USB That Wouldn't Repeat"* — ngay lập tức gợi ý điều gì đó: cùng một USB được thu thập hai lần, nhưng kết quả không giống nhau. Đây là hiện tượng thực trong khoa học pháp chứng số liên quan đến flash memory — USB hiện đại thường có cơ chế wear-leveling làm thay đổi vị trí vật lý của dữ liệu giữa hai lần đọc, dẫn đến hai bản image có hash khác nhau dù nội dung logic không đổi.

Đề bài hỏi MD5 của từng file image. Cái phản xạ đầu tiên là: 50MB mà muốn hash 3 file ~1GB mỗi cái thì phải giải nén ra đĩa đã, rồi mới tính được. Nhưng trước khi làm điều đó mình muốn xem bên trong zip có những gì.

---

## Phần 1: Khám phá cấu trúc zip trước khi giải nén

FTK Imager (AccessData Forensic Toolkit Imager) là một trong những công cụ thu thập chứng cứ số được dùng nhiều nhất trong môi trường Windows. Khi nó tạo ra một bản image — dù là `.001` (raw format), `.E01` (EnCase) hay định dạng khác — nó luôn sinh ra kèm theo một **file log `.txt`** cùng tên với file image.

File log này không phải ghi log lỗi hay debug. Nó là một phần bắt buộc của quy trình forensics vì nó chứa phần `[Computed Hashes]` — MD5 và SHA1 của toàn bộ image, được FTK tính ngay lúc thu thập. Đây là cơ sở để kiểm chứng tính toàn vẹn của chứng cứ (chain of custody).

Nếu file log này tồn tại bên trong zip, mình không cần giải nén file `.001` nặng ~1GB ra đĩa, tính lại hash từ đầu. Mình chỉ cần kéo file log ra. Kiểm tra trước:

```bash
$ unzip -l usb-non-deterministic-files.zip
```

```
Archive:  usb-non-deterministic-files.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2014-05-21 00:08   digitalcorpora/
        0  2014-05-21 00:07   digitalcorpora/linux-dc3dd/
1009778688  2014-05-20 23:59   digitalcorpora/linux-dc3dd/flash-firstrun.dd
1009778688  2014-05-21 00:00   digitalcorpora/linux-dc3dd/flash-secondrun.dd
      488  2014-05-21 00:00   digitalcorpora/linux-dc3dd/flash-secondrun.log
      485  2014-05-20 23:59   digitalcorpora/linux-dc3dd/flash-firstrun.log
        0  2014-05-21 01:32   digitalcorpora/windows7-ftkimager/
     1360  2014-05-21 01:06   digitalcorpora/windows7-ftkimager/flash-secondrun.001.txt
1009778688  2014-05-21 01:06   digitalcorpora/windows7-ftkimager/flash-secondrun.001
     1092  2014-05-21 00:27   digitalcorpora/windows7-ftkimager/flash-firstrun.001.txt
 994926949  2014-05-21 01:06   digitalcorpora/windows7-ftkimager/usb-2
1009778688  2014-05-21 00:26   digitalcorpora/windows7-ftkimager/flash-firstrun.001
 994070821  2014-05-21 00:27   digitalcorpora/windows7-ftkimager/usb-1
    54656  2014-05-21 01:32   digitalcorpora/windows7-ftkimager/ftk-imager-screenshot.png
---------                     -------
6028170603                     14 files
```

Nhìn vào danh sách này mình thấy ngay hai điều:

Thứ nhất, bên trong zip có hai nhánh tool thu thập khác nhau: `linux-dc3dd/` (dùng `dc3dd` — một biến thể forensics của `dd` trên Linux) và `windows7-ftkimager/` (FTK Imager chạy trên Windows 7). Đề bài hỏi cụ thể về FTK Imager, nên mình chỉ nhìn vào thư mục thứ hai.

Thứ hai, trong `windows7-ftkimager/`, có hai file log FTK Imager mình cần:
- `flash-firstrun.001.txt` — 1092 bytes
- `flash-secondrun.001.txt` — 1360 bytes

Hai file log chỉ nặng 1KB mỗi cái, trong khi hai file image `.001` nặng gần 1GB mỗi cái. Mình không giải nén toàn bộ.

---

## Phần 2: Trích xuất đúng hai file log

`unzip` cho phép chỉ định chính xác file cần giải nén, không cần kéo toàn bộ archive ra. Mình dùng flag `-j` để bỏ qua cấu trúc thư mục bên trong zip và đặt hai file thẳng vào thư mục hiện tại:

```bash
$ unzip -j usb-non-deterministic-files.zip \
    "digitalcorpora/windows7-ftkimager/flash-firstrun.001.txt" \
    "digitalcorpora/windows7-ftkimager/flash-secondrun.001.txt"
```

```
Archive:  usb-non-deterministic-files.zip
  inflating: flash-firstrun.001.txt
  inflating: flash-secondrun.001.txt
```

Hai file log được kéo ra trong chưa đầy một giây.

---

## Phần 3: Đọc hash từ file log

Đây là toàn bộ nội dung file `flash-firstrun.001.txt`:

```
Created By AccessData® FTK® Imager 3.1.4.6

Case Information:
Acquired using: ADI3.1.4.6
Case Number:
Evidence Number:
Unique Description:
Examiner:
Notes: First test

--------------------------------------------------------------

Information for C:\Users\FUF\Desktop\digitalcorpora\flash-firstrun:

Physical Evidentiary Item (Source) Information:
[Device Info]
 Source Type: Physical
[Drive Geometry]
 Cylinders: 122
 Tracks per Cylinder: 255
 Sectors per Track: 63
 Bytes per Sector: 512
 Sector Count: 1 972 224
[Physical Drive Information]
 Drive Model: JetFlash Transcend 1GB USB Device
 Drive Serial Number:
 Drive Interface Type: USB
 Removable drive: True
 Source data size: 963 MB
 Sector count:    1972224
[Computed Hashes]
 MD5 checksum:    09817bced4213360c1cb2749aa375523
 SHA1 checksum:   879b25099a3179f8e9dcdf4a8384a3b5b75c92f7

Image Information:
 Acquisition started:   Tue May 20 21:25:16 2014
 Acquisition finished:  Tue May 20 21:26:59 2014
 Segment list:
  C:\Users\FUF\Desktop\digitalcorpora\flash-firstrun.001
```

Và `flash-secondrun.001.txt`:

```
Created By AccessData® FTK® Imager 3.1.4.6

Case Information:
Acquired using: ADI3.1.4.6
Case Number:
Evidence Number:
Unique Description:
Examiner:
Notes: Second test

--------------------------------------------------------------

Information for C:\Users\FUF\Desktop\digitalcorpora\flash-secondrun:

[Physical Drive Information]
 Drive Model: JetFlash Transcend 1GB USB Device
 Drive Interface Type: USB
 Removable drive: True
 Source data size: 963 MB
 Sector count:    1972224
[Computed Hashes]
 MD5 checksum:    2bdab2c08b5b507876bf2f2d7e548cc5
 SHA1 checksum:   9ecf9934d17f1d3953d43d59b0d237a8b560916e

Image Information:
 Acquisition started:   Tue May 20 22:04:18 2014
 Acquisition finished:  Tue May 20 22:06:03 2014

Image Verification Results:
 Verification started:  Tue May 20 22:06:06 2014
 Verification finished: Tue May 20 22:06:34 2014
 MD5 checksum:    2bdab2c08b5b507876bf2f2d7e548cc5 : verified
 SHA1 checksum:   9ecf9934d17f1d3953d43d59b0d237a8b560916e : verified
```

Có một điểm thú vị so sánh giữa hai file log: file secondrun có thêm phần `Image Verification Results` — FTK Imager đã chạy lại một vòng hash kiểm tra sau khi thu thập xong và xác nhận hash khớp (`verified`). Đây là bước forensically sound — đảm bảo dữ liệu ghi xuống image không bị thay đổi trong quá trình thu thập. File firstrun không có bước này, có thể người làm đã bỏ qua hoặc tool không tự động chạy.

---

> Khoảnh khắc mình thấy hai hash MD5 khác nhau hoàn toàn — `09817bced...` và `2bdab2c0...` — dù cùng một thiết bị vật lý — là lúc cái tên bài "The USB That Wouldn't Repeat" có nghĩa hoàn toàn. Flash NAND trong USB hiện đại sử dụng wear-leveling để phân phối đều lượng ghi vào các ô nhớ, tránh để một khu vực bị ghi quá nhiều. Khi `dc3dd` hay FTK Imager đọc image ở mức vật lý (raw physical), nó đọc theo thứ tự sector vật lý — nhưng flash controller đã âm thầm remapped các sector đó giữa hai lần acquisition. Kết quả: cùng một USB, hai lần image, hai hash khác nhau. Đây là lý do trong pháp chứng số người ta vừa phải ghi hash ngay lúc thu thập, vừa cần dùng write blocker để ngăn bất kỳ ghi nào lên thiết bị trong lúc đọc.

---

## Ghép Flag

| Thành phần | Giá trị | Nguồn |
|---|---|---|
| `md5_first` | `09817bced4213360c1cb2749aa375523` | `[Computed Hashes]` trong `flash-firstrun.001.txt` |
| `md5_second` | `2bdab2c08b5b507876bf2f2d7e548cc5` | `[Computed Hashes]` trong `flash-secondrun.001.txt` |

```
grodno{09817bced4213360c1cb2749aa375523_2bdab2c08b5b507876bf2f2d7e548cc5}
```

---

## Bài học rút ra

**1. FTK Imager luôn sinh file log `.txt` — đó là nơi hash được lưu sẵn**
Bất kỳ image nào được tạo bằng FTK Imager đều có file log đi kèm, chứa section `[Computed Hashes]` với MD5 và SHA1. Gặp bài liên quan đến FTK acquisition, tìm file `.txt` cùng tên với file image trước khi làm bất cứ thứ gì khác.

**2. `unzip -j` để kéo file cụ thể ra khỏi zip mà không giải nén toàn bộ**
Khi biết đường dẫn file bên trong zip, lệnh `unzip -j archive.zip "path/to/file"` kéo ra đúng file đó mà không đụng đến phần còn lại. Cực hữu ích khi zip chứa các file image hàng GB mà mình chỉ cần một file log vài KB.

**3. Flash memory không phải thiết bị "deterministic" ở mức vật lý**
Đây là lý do cái tên bài có chữ "Wouldn't Repeat". HDD thông thường đọc cùng sector thì luôn trả về cùng dữ liệu. Flash NAND có wear-leveling controller làm cho mapping sector vật lý → ô nhớ thay đổi theo thời gian. Hai lần acquisition cùng USB có thể cho hash khác nhau — và đây không phải lỗi, đây là đặc tính của thiết bị. Trong forensics, khi gặp flash memory, hash acquired ngay lúc thu thập là chuẩn — đừng dùng hash tính lại sau.

**4. Phần `Image Verification Results` trong log secondrun là dấu hiệu forensically sound**
File log secondrun có thêm bước xác minh sau acquisition: FTK tính lại hash image đã ghi và so khớp với hash lúc đọc nguồn. Đây là quy trình chuẩn để đảm bảo dữ liệu không bị hỏng trong quá trình ghi. Nếu thấy dòng `: verified` ở cuối log, image đó đáng tin cậy hoàn toàn về mặt toàn vẹn dữ liệu.
