---
title: "[Grodno CTF] Philologist - Writeup (Forensics)"
date: "2026.07.21"
author: "admin"
categoryEn: "FORENSICS"
categoryJp: "鑑識"
difficulty: "mid"
---
+++
title = 'Philologist — Write-up'
date = '2026-07-13T23:46:54+07:00'
draft = false
tags = ['GrodnoCTF', 'git', 'git-log']
categories = ['Forensics']
+++

# [Grodno CTF] Philologist - Writeup (Forensics)

**Author:** @meier | **Difficulty:** Medium | **Category:** Forensics / Misc

---

**Tải về đề bài:** [challenge files — OneDrive](https://1drv.ms/u/c/2f661437c52d8a10/IQDR5y97Ew4SRbDPYfWwigO6AaQGhfewXRoSeNQ2Ku2C4nM?e=32JFm0)

## 1. Phân tích ngữ nghĩa học và Thu thập thông tin ban đầu

Thử thách bắt đầu bằng một cái tên khá trừu tượng: **"Philologist"** (Nhà ngôn ngữ học) và một bài thơ viết bằng tiếng Nga.

> **Г**ероев детства мы не судим,
> **И** ведь не правы вовсе тут:
> **Т**огдашних дней грехи забудем,
> **Л**аскаясь тем, что те не врут.
> **О**днажды павши в ноги к смуте, —
> **Г**раницы догмы нас сожрут.

Với kinh nghiệm làm các bài Forensics, mình lập tức tải file đính kèm `filolog.zip` về và giải nén. Bên trong xuất hiện một thư mục mã nguồn chứa thư mục ẩn `.git` và một file ảnh `file1.png`. 

Lúc này, sự chú ý của mình va ngay vào file ảnh. Trong tư duy của một người chơi CTF hệ Forensics, một bức ảnh xuất hiện đơn độc rất dễ chứa dữ liệu ẩn (Steganography). Mình lập tức sử dụng hàng loạt công cụ như `exiftool` để kiểm tra metadata, `strings` để quét các chuỗi văn bản bị nhúng, và cả `zsteg` để dò tìm các bit LSB bị thay đổi. Kết quả hoàn toàn vô vọng. Bức ảnh hoàn toàn sạch sẽ và không chứa bất kỳ thông tin nào có ích. Đây là ngõ cụt đầu tiên.

Bỏ qua bức ảnh, mình quay lại nhìn bài thơ tiếng Nga. Tên bài là "Nhà ngôn ngữ học", vậy thì bản thân đoạn văn bản này phải chứa chìa khoá. Mình thử dịch nghĩa bài thơ sang tiếng Anh, tìm kiếm các từ khoá ẩn, nhưng nội dung chỉ là một bài thơ u ám. Cuối cùng, khi thử áp dụng kỹ thuật thơ khoán thủ (Acrostic) bằng cách ghép các chữ cái đầu tiên của mỗi dòng, mình nhận được chuỗi: **Г - И - Т - Л - О - Г**. 

Áp dụng chuyển tự (transliteration) sang bảng chữ cái Latin, chuỗi này chính là **"GITLOG"**. Manh mối đã được mở khoá: Lệnh `git log`.

## 2. Đánh giá Artifact, Phân tích mã nguồn và Xử lý False Positives

Có được lệnh bài trong tay, mình mở terminal trong thư mục giải nén và gõ:
```bash
git log --all -p
```
Lệnh này in ra lịch sử của 7 commit (từ `part 0` đến `part 6`) kèm theo toàn bộ sự thay đổi của các file trong từng commit (diff). 

Khi lướt qua nội dung code bị thay đổi, mình như bắt được vàng khi thấy hàng tá cấu trúc flag nằm rải rác trong các file `.py`, `.txt`, `.tmp`. Ví dụ như:
- `troll_flag{svdb_gj_t2}`
- `clickbait_flag{_bvtc23v01f}`
- `red_herring_flag{1sgw91mpc04y}`
- `ZGVmaW5pdGVseV9ub3RfZ3JvZG5vezd2N3JiYWxycDh9` (Base64 decode ra `definitely_not_grodno{7v7rbalrp8}`)
- `trust_me_bro_flag{5uimq0pqdaft8}`

Nghĩ rằng đây là một bài Forensics dạng "tìm kim dưới đáy biển", mình đã copy một vài flag có vẻ khả nghi nhất và đem nộp lên hệ thống chấm điểm. Tất nhiên, hệ thống liên tục báo sai (Incorrect). Việc cố gắng thử sai với một danh sách dài các "fake flag" đã ngốn của mình một lượng thời gian đáng kể. Mình chính thức rơi vào hố thỏ (Rabbit hole) mà tác giả đã cố tình giăng ra.

Ngồi tĩnh tâm lại, mình nhận ra mình đã đi chệch hướng so với kim chỉ nam ban đầu. Gợi ý từ bài thơ chỉ rõ ràng duy nhất một từ: **GITLOG**. Nó ngụ ý rằng bản thân "lịch sử của Git" mới là nơi chứa đáp án, chứ không phải "nội dung các file" được lưu bên trong nó.

## 3. Phân tích Metadata của Git và Kỹ thuật Anomaly Detection

Một khi đã phớt lờ phần nội dung file, mình bắt đầu săm soi các thông số của bản thân các commit. 

Mình thử trích xuất chữ cái đầu tiên của từng commit message (`part 0`, `part 1`...) nhưng chúng chỉ toàn là chữ "p", vô nghĩa. 
Mình sử dụng lệnh `git log --format="%T %s"` để kiểm tra mã băm của cây thư mục (Tree hash), kết quả trả về (`8b`, `95`, `09`, `0c`...) cũng là những giá trị thập lục phân lộn xộn không tạo thành chuỗi nào có nghĩa.

Mọi thứ dần đi vào bế tắc cho đến khi mình liệt kê trực tiếp mã băm (Commit Hash - SHA-1) `git log --reverse --format="%H"`của toàn bộ 7 commit theo thứ tự thời gian từ cũ nhất đến mới nhất:
- `part 0`: **`31`**`dbe94b830bf861c963f7de45372ddd9edd54d0`
- `part 1`: **`6f`**`dfa43ba2f2b6d1c4c5e0c5ad92b3337518d50f`
- `part 2`: **`39`**`5b79453ae2968d11ef9daca46717bec68b920b`
- `part 3`: **`66`**`bc2a337c09fb538cbf71f28e5c5e5ffb298b78`
- `part 4`: **`31`**`92d4cb55c224aa4891aad52c34fb63e14f2921`
- `part 5`: **`61`**`0f42ddf7a75f33908a60da201663002ce5a3a8`
- `part 6`: **`39`**`a0f972486a8ae191785177dafcc83e0f42d98f`

Ban đầu, mình không thấy gì đặc biệt vì chúng chỉ là mã băm thông thường. Nhưng khi nhìn dọc theo 2 ký tự Hexadecimal đầu tiên (đại diện cho byte đầu tiên) của cả 7 commit: `31`, `6f`, `39`, `66`, `31`, `61`, `39`, mình chợt nhận ra một điểm kỳ lạ. Toàn bộ các giá trị này đều nằm trọn trong dải mã ASCII chuẩn có thể in ra màn hình (từ `0x20` đến `0x7E`).

Mã SHA-1 của Git được tính toán dựa trên nội dung file, hash commit cha, tác giả và thời gian thực thi. Về nguyên tắc, đầu ra là hoàn toàn ngẫu nhiên. Xác suất để 7 commit ngẫu nhiên liên tiếp đều có byte đầu tiên rơi vào dải ký tự hiển thị được là một con số quá nhỏ để có thể là sự trùng hợp. 

Đến đây, mọi thứ đã sáng tỏ. Đây là kết quả của kỹ thuật **Git Hash Mining** (Brute-forcing mã băm). Tác giả đã dùng script để nhồi nhét khoảng trắng hoặc dịch chuyển thời gian của các commit liên tục, bắt máy tính băm đi băm lại cho đến khi tạo ra được mã SHA-1 có byte khởi đầu khớp với ký tự họ muốn.

## 4. Chuyển đổi hệ cơ số và Trích xuất cờ

Biết được bí mật, công việc cuối cùng chỉ là dịch các byte đầu tiên từ hệ thập lục phân sang mã ASCII tương ứng, tuân thủ theo dòng thời gian của commit:
- `0x31` -> **`1`**
- `0x6f` -> **`o`**
- `0x39` -> **`9`**
- `0x66` -> **`f`**
- `0x31` -> **`1`**
- `0x61` -> **`a`**
- `0x39` -> **`9`**

Ghép chúng lại với nhau, mình thu được chuỗi: `1o9f1a9`. 
Việc cuối cùng là bọc chuỗi này vào định dạng `grodno{}` theo yêu cầu của giải đấu. 

**Flag:** `grodno{1o9f1a9}`
