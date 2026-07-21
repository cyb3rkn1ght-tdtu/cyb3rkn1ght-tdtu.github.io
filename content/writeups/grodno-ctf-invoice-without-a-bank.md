---
title: "CTF Write-up: Invoice Without a Bank"
date: "2026.07.21"
author: "admin"
categoryEn: "FORENSICS"
categoryJp: "鑑識"
difficulty: "mid"
---
+++
title = 'Invoice Without a Bank — Write-up'
date = '2026-07-14T01:14:58+07:00'
draft = false
tags = ['email', 'GrodnoCTF', 'eml', 'phishing']
categories = ['Forensics']
+++

# CTF Write-up: Invoice Without a Bank

**Category:** Email Forensics
**Flag format:** `grodno{filename_subjectid}`
**Flag cuối:** `grodno{Vl6s3kCIKaUvwaUAeY.pdf_6ZFYeMmltso}`

---

## Mô tả bài

> Find the message where a PDF attachment is distributed under the guise of a banking notification. Recover:
> 1. The exact PDF attachment filename
> 2. The identifier from the subject after `Fatura Emitida -`
>
> Password to archive: `Infected`

**Tải về đề bài:** [challenge files — OneDrive](https://1drv.ms/u/c/2f661437c52d8a10/IQDfISqXTs41SIn0YpXKeHPaAXhb_iJLsgnNQQKfRL0ovyw?e=3gNPz6)

---

## Nhận file và kiểm tra nhanh

File zip được bảo vệ bằng mật khẩu `Infected`. Giải nén xong thì thấy một thư mục `public/emails/` với 10 file `.eml` bên trong:

```bash
$ unzip -P Infected "Invoice Without a Bank.protected.zip"
$ ls -la public/emails/
```

```
total 1464
drwxr-xr-x 2 user user   4096 Jul 12 06:30 .
drwxr-xr-x 3 user user   4096 Jul 12 06:30 ..
-rw-r--r-- 1 user user 144082 Jul 12 06:30 sample-1000.eml
-rw-r--r-- 1 user user 148961 Jul 12 06:30 sample-1008.eml
-rw-r--r-- 1 user user 122334 Jul 12 06:30 sample-1014.eml
-rw-r--r-- 1 user user 160919 Jul 12 06:30 sample-1324.eml
-rw-r--r-- 1 user user 124925 Jul 12 06:30 sample-189.eml
-rw-r--r-- 1 user user 237363 Jul 12 06:30 sample-405.eml
-rw-r--r-- 1 user user 127160 Jul 12 06:30 sample-591.eml
-rw-r--r-- 1 user user  33134 Jul 12 06:30 sample-62.eml
-rw-r--r-- 1 user user 112324 Jul 12 06:30 sample-717.eml
-rw-r--r-- 1 user user 161713 Jul 12 06:30 sample-922.eml
```

Tên file toàn kiểu `sample-xxx.eml` — không có gợi ý gì về nội dung. Dung lượng dao động từ 33KB đến 237KB. File `.eml` là định dạng email thô theo chuẩn RFC 5322: phần đầu là các header dạng `Key: Value` (From, To, Subject, Date...), phần sau là nội dung email và file đính kèm — tất cả đều là text thuần, đọc được bằng bất kỳ công cụ nào. Mình không đời nào mở từng file bằng tay, dùng CLI thôi.

---

## Phần 1: Tìm đúng email trong 10 file

Mình cần tìm email giả mạo thông báo ngân hàng gửi kèm file PDF. Bài yêu cầu lấy hai thứ: tên file PDF đính kèm và phần ID trong tiêu đề sau chuỗi `Fatura Emitida -`.

Nghĩ đơn giản trước: bài nói đến PDF, vậy cứ xem có bao nhiêu email đính kèm file PDF là đủ để khoanh vùng.

```bash
$ grep -ri "\.pdf" public/emails/
```

```
public/emails/sample-717.eml:	name="Vl6s3kCIKaUvwaUAeY.pdf"
public/emails/sample-717.eml:	filename="Vl6s3kCIKaUvwaUAeY.pdf"
public/emails/sample-1014.eml:Content-Type: application/pdf; name="StatementAmazon#CASE-3987187467.pdf"
public/emails/sample-1014.eml:	filename="StatementAmazon#CASE-3987187467.pdf"
public/emails/sample-1324.eml:Content-Type: application/octet-stream; name=ZGWWYaVnFL.pdf
public/emails/sample-62.eml:Content-Type: application/pdf; name="YSXUqT4G.pdf"
public/emails/sample-62.eml:Content-Disposition: attachment; filename="YSXUqT4G.pdf"
public/emails/sample-922.eml:Content-Type: application/pdf; name="IRS.GovTAXReturn#Docx-REFF8492785.pdf"
public/emails/sample-922.eml:	filename="IRS.GovTAXReturn#Docx-REFF8492785.pdf"
public/emails/sample-189.eml:	name="Bitcoin.Transfer.0.7495.BTCqrfnz8sNGbYuasI7iVes2P.pdf"
public/emails/sample-189.eml:	filename="Bitcoin.Transfer.0.7495.BTCqrfnz8sNGbYuasI7iVes2P.pdf"
public/emails/sample-1000.eml:	name="csWuYjyqO2IR.pdf"
public/emails/sample-1000.eml:	filename="csWuYjyqO2IR.pdf"
public/emails/sample-405.eml:Content-Type: application/pdf; name="Request for Quotation.pdf"
public/emails/sample-405.eml:Content-Disposition: attachment; filename="Request for Quotation.pdf"
public/emails/sample-1008.eml:	name="Fa0ldxfjHYJ.pdf"
public/emails/sample-1008.eml:	filename="Fa0ldxfjHYJ.pdf"
```

9 trên 10 email đều đính kèm PDF — chỉ mỗi `sample-591.eml` là không có. Đây là dataset phishing mẫu, chuyện đính kèm PDF để giả làm hóa đơn, báo cáo ngân hàng, thông báo Amazon... là chiêu phổ biến đến mức lọc theo định dạng file không giúp ích được gì.

> Mình dừng lại và đọc kỹ lại đề. Đề yêu cầu tìm email có tiêu đề chứa chuỗi `Fatura Emitida -` — đây là tiếng Bồ Đào Nha, nghĩa là "Hóa đơn đã phát hành". Đề bài đã trao thẳng vào tay mình một chuỗi định danh cực kỳ đặc trưng trong dòng Subject. Đáng ra mình phải nhìn ra cái này từ đầu, lọc theo đó luôn — thay vì đi lọc theo định dạng file đính kèm rồi bị chết trong nhiễu.

Chuyển sang lọc theo tiêu đề. Trường Subject trong email thường được viết theo dạng `Subject: <nội dung>` — mình thêm prefix đó vào từ khóa tìm kiếm để tránh lọc trúng nội dung body email:

```bash
$ grep -rn "Subject: Fatura Emitida -" public/emails/
```

```
public/emails/sample-717.eml:65:Subject: Fatura Emitida - 6ZFYeMmltso
```

Chỉ có một kết quả duy nhất. File cần tìm là `sample-717.eml`, nằm ở dòng 65 của file. Dòng Subject đã hiện luôn phần ID cần lấy: `6ZFYeMmltso`.

---

## Phần 2: Lấy tên file đính kèm PDF

Đã xác định được email mục tiêu, bước tiếp theo là lấy tên file PDF đính kèm. Mình biết file nào cần xem rồi, nhưng không thể `cat` thẳng ra terminal được. File `.eml` có đính kèm sẽ nhúng toàn bộ nội dung nhị phân của PDF vào file text dưới dạng chuỗi Base64 — tức là hàng chục nghìn dòng ký tự `A-Za-z0-9+/=` chạy liên tục. Thử thì biết ngay terminal sẽ giật, scroll không kịp, và mình cũng không rút ra được gì từ đống đó.

Cách làm đúng là nhìn vào cấu trúc MIME của email. Khi một email có file đính kèm, phần header của phần đính kèm đó sẽ có hai trường quan trọng:
- `Content-Type: application/pdf; name="tên-file.pdf"` — khai báo loại dữ liệu
- `Content-Disposition: attachment; filename="tên-file.pdf"` — chỉ định cách mail client xử lý (hiển thị inline hay lưu thành file)

Tên file thực tế nằm trong thuộc tính `filename=`. Mình `grep` thẳng vào đó:

```bash
$ grep -i "filename=" public/emails/sample-717.eml
```

```
        filename="Vl6s3kCIKaUvwaUAeY.pdf"
```

Một dòng duy nhất, tên file là `Vl6s3kCIKaUvwaUAeY.pdf`. Tên file được tạo ngẫu nhiên — kiểu đặt tên này thường gặp trong các công cụ phishing tự động để tránh bị nhận diện theo tên cố định.

---

## Ghép Flag

| Thành phần | Giá trị | Nguồn |
|---|---|---|
| `filename` | `Vl6s3kCIKaUvwaUAeY.pdf` | Trường `filename=` trong MIME header của `sample-717.eml` |
| `subjectid` | `6ZFYeMmltso` | Phần sau `Fatura Emitida -` trong dòng Subject của `sample-717.eml` |

```
grodno{Vl6s3kCIKaUvwaUAeY.pdf_6ZFYeMmltso}
```

---

## Bài học rút ra

**1. Trong bộ dữ liệu phishing, lọc theo định dạng file đính kèm là vô dụng**
Tất cả các email phishing đều dùng PDF, Word, ZIP làm file đính kèm vì đó là thứ người nhận hay mở. Khi dataset là tập hợp các mẫu phishing, thì PDF xuất hiện ở khắp nơi. Cái có giá trị để lọc là các chuỗi đặc trưng trong tiêu đề hoặc nội dung: tên thương hiệu, ngôn ngữ cụ thể, định dạng subject riêng biệt. Đề bài thường đã nhúng sẵn IoC này — đọc kỹ trước khi bắt tay vào lọc.

**2. Hiểu cấu trúc MIME của file `.eml` để grep đúng trường**
File `.eml` có đính kèm sẽ nhúng toàn bộ dữ liệu nhị phân vào dạng Base64 bên trong file text — không bao giờ `cat` ra terminal. Thứ mình cần luôn nằm trong các header nhỏ phía trên phần Base64: `Content-Disposition: attachment; filename="..."` là trường đáng tin cậy nhất để lấy tên file đính kèm, vì đây là phần mail client dùng để quyết định lưu file với tên gì.

**3. Thêm prefix header khi grep để tránh lọc trúng nội dung body**
Nếu chỉ grep `Fatura Emitida -` mà không kèm `Subject:` phía trước, lệnh có thể khớp cả với nội dung HTML hay plain-text bên trong email. Với email phishing, nội dung body thường lặp lại từ khóa của tiêu đề để tạo urgency — nên grep `Subject: Fatura Emitida -` để chắc chắn chỉ lọc header.
