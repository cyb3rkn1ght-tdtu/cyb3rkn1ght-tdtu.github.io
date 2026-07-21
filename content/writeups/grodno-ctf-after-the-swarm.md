---
title: "CTF Write-up: After The Swarm"
date: "2026.07.21"
author: "admin"
categoryEn: "FORENSICS"
categoryJp: "鑑識"
difficulty: "mid"
---
+++
title = 'After The Swarm — Write-up'
date = '2026-07-14T01:01:48+07:00'
draft = false
tags = ['GrodnoCTF', 'pcap', 'mirai']
categories = ['Forensics', 'Networking', 'IoT']
+++

# CTF Write-up: After The Swarm

**Category:** Forensics / Network
**Flag format:** `grodno{artifact_httpport_c2port_c2len_s2len1_s2len2_s2len3}`
**Flag cuối:** `grodno{armv6l_51370_50178_11_13_4_6}`

---

## Mô tả bài

> We obtained a large network capture of an infected IoT device.
> You need to reconstruct not a single artifact, but three linked stages of the infection chain:
> - The start of the first mass propagation wave on 8081/tcp.
> - The only HTTP object requested after that wave had already started.
> - The first successful 4554/tcp control-exchange that happened after that late HTTP request.
> 
> Then recover:
> - The name of the late HTTP object.
> - The source TCP port of that HTTP request.
> - The source TCP port of the control session.
> - The size of the first client payload in that control session.
> - The sizes of the first three server payloads in the same session.

**Tải về đề bài:** [challenge files — OneDrive](https://1drv.ms/u/c/2f661437c52d8a10/IQDL_EvDMIzyS7R5fQ6VKniXAZe-UImTDbuLLucAV5zQSoM?e=F5pYLw)

---

## Nhận file và kiểm tra nhanh

Tải file zip của challenge về, việc đầu tiên mình làm luôn là liệt kê nội dung bên trong file zip thay vì giải nén bừa bãi. Nhất là khi nghe đồn file pcap này cực kỳ nặng. Mình dùng `unzip -l` để kiểm tra:

```bash
$ unzip -l After_The_Swarm.zip
```

```
Archive:  After_The_Swarm.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
1381228544  2022-04-13 17:40   mirai_revenge.pcap
---------                     -------
1381228544                     1 file
```

Nhìn thông số `Length` mà giật cả mình: file pcap chưa giải nén bên trong nặng tới **1.38 GB**!
Nếu mình giải nén toàn bộ ra đĩa cứng rồi dùng `tshark` hay `tcpdump` đọc trực tiếp file `.pcap` đó, ổ đĩa sẽ phải gánh lượng I/O cực lớn và máy tính có thể bị treo (đơ) ngay lập tức do thiếu tài nguyên RAM/Disk cache. Còn nếu mở trực tiếp bằng Wireshark GUI thì coi như xác định phải restart máy.

> [!IMPORTANT]
> **Giải pháp tối ưu:** Mình quyết định **không giải nén** file pcap ra đĩa. Thay vào đó, mình sẽ dùng lệnh `unzip -p` để stream trực tiếp luồng dữ liệu pcap đã giải nén qua chuẩn stdout (standard output), rồi dùng pipe (`|`) chuyển tiếp thẳng vào `tcpdump` hoặc `tshark` với tùy chọn đọc từ stdin (`-r -`). 
> Cách này giúp tiết kiệm tối đa RAM và dung lượng ổ cứng, đồng thời tốc độ xử lý nhanh hơn rất nhiều do không phải ghi/đọc file từ ổ đĩa.

---

## Phần 1: Xác định thời điểm đợt càn quét mạng bắt đầu (Mass Propagation Wave trên port 8081)

### Phát hiện vấn đề

Mục tiêu đầu tiên là tìm mốc thời gian bắt đầu của đợt càn quét mạng trên port 8081/tcp.
Theo hành vi đặc trưng của các botnet IoT (như Mirai), khi thiết bị bắt đầu càn quét, nó sẽ gửi liên tục các gói tin TCP SYN đến cổng 8081 của hàng loạt IP ngẫu nhiên. Số lượng gói tin trên port này sẽ tăng vọt đột ngột từ 0 lên hàng trăm gói mỗi giây.

Để tìm mốc thời gian này, mình stream dữ liệu pcap qua `tcpdump`, lọc các gói tin liên quan đến port 8081, sau đó gom nhóm và đếm số lượng gói tin theo từng giây:

```bash
$ unzip -p After_The_Swarm.zip | tcpdump -n -r - "tcp port 8081" 2>/dev/null | awk '{print $1}' | cut -d'.' -f1 | uniq -c | head -n 10
```

```
    320 02:50:48
    320 02:50:49
    320 02:50:50
    640 02:50:51
    640 02:50:52
    640 02:50:53
    640 02:50:54
    640 02:50:55
    640 02:50:56
    640 02:50:57
```

### Phân tích

Từ kết quả trên, trước giây `02:50:48` hoàn toàn không có lưu lượng nào trên port 8081. Nhưng ngay tại giây `02:50:48`, số lượng gói tin đột ngột xuất hiện ở mức 320 gói/giây và tăng lên 640 gói/giây ở các giây sau. Đây chính xác là thời điểm đợt càn quét bắt đầu.

Để có mốc thời gian Epoch chính xác để so sánh cho các phần tiếp theo, mình chạy lệnh in ra timestamp dạng Epoch của các gói tin đầu tiên đi qua port 8081:

```bash
$ unzip -p After_The_Swarm.zip | tcpdump -tt -n -r - "tcp port 8081" 2>/dev/null | head -n 5
```

```
1551383448.186215 IP 192.168.1.193.24159 > 108.116.222.190.8081: Flags [S], seq 1819598526, win 35766, length 0
1551383448.186221 IP 192.168.1.193.24159 > 108.116.222.190.8081: Flags [S], seq 1819598526, win 35766, length 0
1551383448.186462 IP 192.168.1.193.24159 > 197.142.48.202.8081: Flags [S], seq 3314430154, win 35766, length 0
1551383448.186468 IP 192.168.1.193.24159 > 197.142.48.202.8081: Flags [S], seq 3314430154, win 35766, length 0
1551383448.186470 IP 192.168.1.193.24159 > 197.37.170.62.8081: Flags [S], seq 3307579966, win 35766, length 0
```

Mốc thời gian Epoch bắt đầu đợt quét là: `1551383448`.

---

## Phần 2: Tìm "The late HTTP object" (File tải về sau khi càn quét bắt đầu)

### Phát hiện vấn đề

Đề bài yêu cầu tìm *"The only HTTP object requested after that wave had already started"*.
Tức là mình phải tìm request HTTP GET tải file độc hại được thực hiện **sau** mốc thời gian `1551383448`.

Mình sẽ stream pcap qua `tshark` để lọc ra tất cả các HTTP GET requests, lấy mốc thời gian Epoch, URI của file được tải, và source TCP port:

```bash
$ unzip -p After_The_Swarm.zip | tshark -r - -Y "http.request.method == GET" -T fields -e frame.time_epoch -e http.request.uri -e tcp.srcport 2>/dev/null
```

```
1551383431.241322000    /mips      51358
1551383433.235805000    /mipsel    51360
1551383436.194848000    /sh4       51362
1551383444.854627000    /x86       51364
1551383446.309299000    /armv7l    51366
1551383449.395774000    /armv6l    51370
1551383467.263144000    /i686      51374
1551383469.641900000    /powerpc   51376
1551383471.219501000    /i586      51378
1551383475.642961000    /m68k      51380
1551383480.213333000    /sparc     51382
1551383485.002585000    /armv4l    51384
1551383486.648890000    /armv5l    51386
1551383489.245902000    /440fp     51388
```

---

### Sai lầm 1: Chọn HTTP GET request đầu tiên trong danh sách

Lúc đầu nhìn vào danh sách, mình bị hút mắt ngay bởi dòng đầu tiên `/mips` lúc `1551383431.241322000`. Tuy nhiên, mốc thời gian này là **trước** khi đợt càn quét bắt đầu (`1551383448`). Đề bài yêu cầu tìm đối tượng được tải **sau** khi đợt quét đã chạy rồi.

---

### Khoảnh khắc nhận ra

> Đợt quét bắt đầu lúc `1551383448`. Request đầu tiên xảy ra ngay sau đó là tải `/armv6l` lúc `1551383449.395774000` với source port `51370`.
> 
> Nhưng tại sao đề bài lại gọi nó là *"the ONLY HTTP object requested after that wave had already started"* (đối tượng HTTP **duy nhất**)? Trong danh sách rõ ràng vẫn còn `/i686`, `/powerpc`... được tải sau đó nữa cơ mà?
> 
> Hóa ra, kịch bản lây nhiễm của mã độc IoT thường tải hàng loạt phiên bản cho các kiến trúc CPU khác nhau. Khi thiết bị chạy thành công file nhị phân tương thích với CPU của nó (ở đây là `armv6l`), malware sẽ ngay lập tức chiếm quyền kiểm soát thiết bị và thiết lập kết nối điều khiển C2. Mọi yêu cầu tải các file kiến trúc khác ở phía sau đều vô nghĩa hoặc bị ngắt quãng. Vì vậy, `/armv6l` là file payload thực sự hoạt động và là duy nhất dẫn đến giai đoạn lây nhiễm tiếp theo.

Kết quả:
- Tên HTTP object: `armv6l`
- Source TCP Port: `51370`

---

## Phần 3: Phân tích phiên điều khiển C2 (Port 4554) và Kích thước Payload

### Phát hiện vấn đề

Mục tiêu tiếp theo là tìm phiên kết nối C2 thành công đầu tiên trên port 4554/tcp xảy ra sau thời điểm tải file `/armv6l` (`1551383449.395774`).
Một kết nối TCP thành công bắt buộc phải hoàn thành quá trình bắt tay 3 bước (3-way handshake). Cụ thể, mình cần lọc các gói tin chứa cờ `SYN-ACK` phản hồi từ server C2 gửi về cho client.

---

### Sai lầm 1: Lấy ngay gói tin SYN đầu tiên gửi đến port 4554

Nếu mình vội vàng lọc tất cả các gói tin có cờ `SYN` gửi đến port 4554 sau mốc thời gian trên:

```bash
$ unzip -p After_The_Swarm.zip | tshark -r - -Y "tcp.dstport == 4554 && tcp.flags.syn == 1" -T fields -e frame.time_epoch -e tcp.srcport | head -n 5
```

```
1551383432.112048000    50170
1551383434.502948000    50172
1551383445.602984000    50174
```

Nếu chọn source port `50170` thì sẽ sai bét, vì đây chỉ là những nỗ lực kết nối đơn phương từ các tiến trình hoặc thiết bị khác nhưng không thành công (không có phản hồi từ server).

---

### Phân tích

Để tìm kết nối được thiết lập thành công thực sự, mình lọc các gói tin chứa cả hai cờ `SYN` và `ACK` (SYN-ACK) trên port 4554:

```bash
$ unzip -p After_The_Swarm.zip | tshark -r - -Y "tcp.port == 4554 && tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e frame.time_epoch -e tcp.srcport -e tcp.dstport 2>/dev/null | head -n 5
```

```
1551383452.609428000    4554    50178
1551383452.609435000    4554    50178
1551383499.393345000    4554    50196
1551383499.393357000    4554    50196
```

Kết nối C2 thành công đầu tiên sau mốc tải file (`1551383449.395774`) chính là phiên với client port là **50178** vào lúc `1551383452.609428`.
- Source TCP Port của phiên C2: `50178`

### Đo lường kích thước payload

Bây giờ, mình cần xác định kích thước gói dữ liệu (payload size) đầu tiên do client gửi lên và 3 gói dữ liệu tiếp theo do server trả về trong phiên kết nối của port `50178`.

Mình lọc các gói tin của port này, in ra source port, destination port, độ dài dữ liệu TCP (`tcp.len`), và chuỗi các cờ TCP (`tcp.flags.str`). Mình dùng `uniq` để loại bỏ các gói tin bị ghi nhận lặp do cơ chế bắt gói trên nhiều interface:

```bash
$ unzip -p After_The_Swarm.zip | tshark -r - -Y "tcp.port==50178" -T fields -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.flags.str 2>/dev/null | uniq | head -n 12
```

```
50178   4554    0       ··········S·
4554    50178   0       ·······A··S·
50178   4554    0       ·······A····
50178   4554    11      ·······AP···
4554    50178   0       ·······A····
4554    50178   13      ·······AP···
50178   4554    0       ·······A····
4554    50178   4       ·······AP···
50178   4554    0       ·······A····
4554    50178   6       ·······AP···
50178   4554    0       ·······A····
4554    50178   4       ·······AP···
```

Dựa vào các gói tin mang dữ liệu thực tế (chứa cờ `AP` - PUSH/ACK và `tcp.len > 0`), luồng trao đổi dữ liệu diễn ra như sau:
1. Gói dữ liệu đầu tiên từ Client gửi lên Server (50178 -> 4554): `tcp.len` = **11**
2. Gói dữ liệu thứ 1 từ Server gửi về Client (4554 -> 50178): `tcp.len` = **13**
3. Gói dữ liệu thứ 2 từ Server gửi về Client (4554 -> 50178): `tcp.len` = **4**
4. Gói dữ liệu thứ 3 từ Server gửi về Client (4554 -> 50178): `tcp.len` = **6**

Kết quả:
- Client payload size (`c2len`): `11`
- 3 Server payload sizes (`s2len1`, `s2len2`, `s2len3`): `13`, `4`, `6`

---

## Ghép Flag

| Thành phần | Giá trị | Nguồn |
|---|---|---|
| `artifact` | `armv6l` | HTTP GET request lúc `1551383449` |
| `httpport` | `51370` | TCP Source Port của HTTP GET `/armv6l` |
| `c2port` | `50178` | TCP Source Port của kết nối C2 thành công đầu tiên |
| `c2len` | `11` | Chiều dài gói dữ liệu client gửi lên đầu tiên |
| `s2len1` | `13` | Chiều dài gói dữ liệu server phản hồi thứ nhất |
| `s2len2` | `4` | Chiều dài gói dữ liệu server phản hồi thứ hai |
| `s2len3` | `6` | Chiều dài gói dữ liệu server phản hồi thứ ba |

```
grodno{armv6l_51370_50178_11_13_4_6}
```

---

## Bài học rút ra

**1. Kỹ thuật stream trực tiếp pcap từ file zip (`unzip -p`)**
Đối với các file capture cực kỳ lớn (trên 1GB), việc giải nén ra đĩa cứng sẽ gây tốn tài nguyên I/O và dễ làm đơ hệ thống. Sử dụng `unzip -p` để stream trực tiếp luồng bytes đã giải nén vào stdin của `tcpdump` hay `tshark` qua dấu `-` là phương án tối ưu, không tốn thêm dung lượng đĩa và hạn chế tối đa việc treo máy.

**2. Tầm quan trọng của phân tích timeline**
Tái dựng đúng chuỗi sự kiện theo thứ tự thời gian Epoch giúp liên kết các giai đoạn lây nhiễm của mã độc: Quét cổng 8081 -> HTTP tải file binary -> Kết nối C2 trên port 4554.

**3. Phân biệt nỗ lực kết nối và kết nối thành công**
Lọc gói tin C2 bằng cờ SYN-ACK (`tcp.flags.syn==1 && tcp.flags.ack==1`) giúp ta lọc bỏ các gói SYN quét mạng đơn phương không thành công, xác định chính xác phiên điều khiển C2 thực tế.

**4. Xác định payload bằng cờ PUSH/ACK**
Khi tính kích thước gói tin điều khiển, bỏ qua các gói bắt tay/ACK thông thường (`len=0`). Tập trung vào các gói mang cờ PUSH (`AP` trong tshark) để xác định đúng kích thước dữ liệu truyền tải thực tế.

**5. Lọc nhiễu trùng lặp gói tin**
Khi capture trên nhiều card mạng ảo/vật lý cùng lúc, file pcap sẽ ghi nhận các gói tin bị trùng lặp. Cần dùng `uniq` để lọc bớt dữ liệu thừa trước khi đếm kích thước payload để tránh kết quả bị sai lệch.
