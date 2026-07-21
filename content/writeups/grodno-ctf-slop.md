---
title: "CTF Write-up: Slop"
date: "2026.07.21"
author: "admin"
categoryEn: "WEB"
categoryJp: "アクション"
difficulty: "mid"
---
+++
title = 'Slop — Write-up'
date = '2026-07-14T01:41:05+07:00'
draft = false
tags = ['GrodnoCTF', 'llm', 'qwen']
categories = ['AI', 'Steganography']
+++

# CTF Write-up: Slop

**Category:** AI / Steganography / Misc
**Flag format:** `grodno{...}`
**Flag cuối:** `grodno{stego_can_be_even_like_this}`

---

## Mô tả bài

> I received a very strange message. It seems the sender has undergone AI-ization
>
> Will be useful:
>
> Model: Qwen/Qwen2.5-0.5B-Instruct-GGUF
> Revision: 9217f5db79a29953eb74d5343926648285ec7e67
> File: qwen2.5-0.5b-instruct-q4_k_m.gguf
> Runtime: llama-cpp-python==0.3.16
> Flag format: grodno{}

**Tải về đề bài:** [challenge files — OneDrive](https://1drv.ms/f/c/2f661437c52d8a10/IgD-Vke1R8LiS6a2DgN-I4ekASw-1r-k8t24cxKh3RX1CQA?e=j0mHCL)

File đính kèm: `message.txt`

---

## Nhận file và kiểm tra nhanh

File duy nhất được cung cấp là `message.txt`. Mình luôn bắt đầu bằng cách đọc file ở mức thấp nhất có thể — không suy diễn ý nghĩa, chỉ xem byte thật:

```bash
$ file message.txt && wc -c message.txt
```

```
message.txt: ASCII text
78 message.txt
```

```bash
$ xxd -g 1 message.txt
```

```
00000000: 41 20 73 68 6f 72 74 20 72 65 63 69 70 65 20 66  A short recipe f
00000010: 6f 72 20 61 20 77 69 6e 74 65 72 20 76 65 67 65  or a winter vege
00000020: 74 61 62 6c 65 20 73 6f 75 70 3a 0a 50 72 65 70  table soup:.Prep
00000030: 61 72 65 20 6f 72 20 73 61 6c 6d 6f 6e 20 73 74  are or salmon st
00000040: 65 61 69 6d 61 6c 6c 20 73 74 6f 63 6b 2c        eaimall stock,
```

Chỉ 78 byte, ASCII thuần, không có byte ẩn, không trailing data. Nội dung là:

```
A short recipe for a winter vegetable soup:
Prepare or salmon steaimall stock,
```

Câu đầu trông tự nhiên. Câu thứ hai thì kỳ lạ — "steaimall" không phải từ tiếng Anh nào tồn tại. Không có byte ẩn ở tầng file.

Mình dừng lại đọc kỹ hint của đề. Bình thường một challenge stego chỉ cần cho file, không cần nói model gì. Đây đề cho đúng model name, revision hash (SHA1 của commit trên HuggingFace), tên file GGUF, và cả phiên bản runtime Python. Đây là dấu hiệu rất rõ: **lời giải phụ thuộc vào hành vi cụ thể của model đó với runtime đó**, không phải phân tích văn bản thông thường.

---

## Phần 1: Nền tảng — LLM sinh text như thế nào

Để hiểu bài này, cần hiểu cơ chế bên trong của LLM. Đây không phải kiến thức nâng cao — đây là nền tảng để nhìn ra ý tưởng của người ra đề.

![Kiến trúc Transformer và cơ chế logits](images/llm_architecture.png)

**Token là gì?** LLM không xử lý ký tự hay từ — nó xử lý **token**, là các đơn vị văn bản được chia theo từ điển riêng của model. Tokenizer của Qwen chia text thành các mảnh như sau:

```
"Hello world"   →  ["Hello", " world"]           (2 token)
"steaimall"     →  [" ste", "aim", "all"]         (3 token)
"grodno{"       →  ["gr", "odno", "{"]            (3 token)
```

Một từ có thể thành nhiều token. Một token có thể là nhiều ký tự. Điều này quan trọng vì **dữ liệu ẩn trong bài này đi theo đơn vị token, không phải ký tự**.

**Logits là gì?** Sau khi nhận một chuỗi token đầu vào, model chạy qua nhiều lớp Transformer rồi ở lớp cuối cùng xuất ra một mảng số — gọi là **logits**. Mảng này có kích thước bằng số token trong vocabulary (~151,936 token với Qwen2.5-0.5B). Mỗi số biểu diễn "điểm số" của model cho token tương ứng — token nào có điểm cao hơn thì model dự đoán khả năng xuất hiện tiếp theo cao hơn.

**Rank là gì?** Nếu sắp xếp toàn bộ 151,936 logits theo thứ tự giảm dần, vị trí của một token trong danh sách đó là **rank** của token đó:

- Token có điểm cao nhất → **rank 0**
- Token có điểm cao thứ hai → **rank 1**
- Token có điểm cao thứ 49 → **rank 48**
- ...

Khi model sinh text theo cách thông thường (greedy decoding), nó luôn chọn token có rank 0. Nhưng không ai bắt buộc phải làm vậy.

---

## Phần 2: Đặt giả thuyết — cover text mang rank ẩn

Từ hai quan sát trên — câu hai vô nghĩa và đề chỉ định model cụ thể — mình đặt giả thuyết:

> Người gửi không viết câu hai bằng tay. Họ dùng model Qwen để sinh từng token theo một **dãy rank được chọn trước**. Dãy rank đó chính là dữ liệu ẩn. Cover text kỳ lạ là kết quả.

Cụ thể hơn, mình hình dung quá trình encode như sau:

1. Bắt đầu với prompt: `A short recipe for a winter vegetable soup:\n`
2. Đưa prompt vào model → model xuất logits cho token tiếp theo
3. Thay vì chọn rank 0 (token model thích nhất), người gửi chọn token ở rank **48** → token đó là `Prepare`
4. Feed `Prepare` trở lại vào model → model xuất logits mới
5. Lần này chọn token ở rank **69** → token đó là ` or`
6. Tiếp tục...
7. Chuỗi rank `[48, 69, ...]` là flag được giấu; chuỗi token `Prepare or salmon...` là cover text

Để **giải mã**, mình cần:
1. Tái tạo đúng vòng sinh token đó trên cùng model
2. Tại mỗi bước, đọc rank của token thật trong cover text
3. Dùng dãy rank để decode từ một context biết trước — đây chính là lúc flag format `grodno{` có ích

![Luồng encode (trái) và decode (phải) của AI steganography](images/ai_stego_encode_decode.png)

---

## Phần 3: Setup môi trường — phải khớp chính xác

Trước khi chạy bất kỳ lệnh phân tích nào, mình phải setup đúng environment. Lý do: logits của một GGUF quantized model phụ thuộc vào cách thư viện C++ backend tính toán. Phiên bản `llama-cpp-python==0.3.17` có thể cho logits khác với `0.3.16`, dẫn đến rank khác, dẫn đến flag sai. Revision hash của model cũng quan trọng vì HuggingFace cho phép cùng tên nhưng khác commit.

```bash
$ UV_CACHE_DIR=/tmp/uv-cache uv venv .venv
$ uv pip install --python .venv/bin/python llama-cpp-python==0.3.16
```

```
Installed 6 packages in 43ms
 + llama-cpp-python==0.3.16
 + numpy==2.5.1
 ...
```

```bash
$ mkdir -p models
$ curl -L \
  -o models/qwen2.5-0.5b-instruct-q4_k_m.gguf \
  "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf"
```

```
100  468M  100  468M    0     0  5872k      0  0:01:21  0:01:21 --:--:-- 7199k
```

Xác nhận:

```bash
$ .venv/bin/python -c "import llama_cpp; print(llama_cpp.__version__)"
```

```
0.3.16
```

---

## Phần 4: Tokenize message — dữ liệu ẩn đi theo token, không theo ký tự

Mình cần biết chính xác cover text được tokenize thành những gì, vì mỗi token tương ứng một rank trong dãy rank ẩn.

```bash
$ .venv/bin/python analyze_message.py
```

```
prompt='A short recipe for a winter vegetable soup:\n'
continuation='Prepare or salmon steaimall stock,'

prompt: 9 tokens
 0     32 'A'
 1   2805 ' short'
 2  11116 ' recipe'
 3    369 ' for'
 4    264 ' a'
 5  12406 ' winter'
 6  35481 ' vegetable'
 7  19174 ' soup'
 8    510 ':\n'

continuation: 8 tokens
 0  50590 'Prepare'
 1    476 ' or'
 2  40320 ' salmon'
 3   4087 ' ste'
 4   2640 'aim'
 5    541 'all'
 6   5591 ' stock'
 7     11 ','
```

Chú ý: từ `steaimall` bị tokenizer chia thành 3 token riêng: `ste` + `aim` + `all`. Đây là subword tokenization — tokenizer không biết "steaimall" là từ gì nên nó chia theo các pattern phổ biến trong training data.

Tổng cộng có **8 token** trong continuation. Vậy dãy rank sẽ có 8 phần tử. Flag body cũng sẽ có 8 token — nhưng mỗi token có thể là nhiều ký tự, nên flag body dài hơn 8 ký tự là hoàn toàn bình thường.

---

## Phần 5: Dead-end — lấy rank bằng batch evaluation

Cách tự nhiên đầu tiên mình nghĩ đến: eval toàn bộ chuỗi một lần, rồi đọc logits tại từng vị trí. Trong `llama-cpp-python`, khi gọi `llm.eval(all_tokens)` với `logits_all=True`, thư viện lưu logits của mọi vị trí vào `llm.scores`. Mình dùng cách này:

```python
all_tokens = prompt_tokens + continuation_tokens
llm.eval(all_tokens)

for i, token_id in enumerate(continuation_tokens):
    pos = len(prompt_tokens) + i
    logits = llm.scores[pos - 1]      # logits của vị trí trước token này
    order = np.argsort(logits)[::-1]   # sort giảm dần
    rank = int(np.where(order == token_id)[0][0])
    print(f"token '{piece(llm, token_id)}' → rank {rank}")
```

Kết quả:

```
continuation ranks (batch eval):
token 'Prepare'  → rank 41
token ' or'      → rank 62
token ' salmon'  → rank 1959
token ' ste'     → rank 75
token 'aim'      → rank 155
token 'all'      → rank 135
token ' stock'   → rank 26
token ','        → rank 0

ranks = [41, 62, 1959, 75, 155, 135, 26, 0]
```

Nhìn dãy này mình thử nhiều hướng giải mã:

**Thử 1 — Xem rank như ASCII byte:** Chuyển `[41, 62, 1959, ...]` thành ký tự ASCII. `41` = `)`, `62` = `>` — trông như rác. Hơn nữa `1959 > 255` nên không thể là ASCII byte. Loại.

**Thử 2 — Ghép 11-bit:** Vì `1959 < 2048 = 2^11`, mình thử coi mỗi rank là 11 bit và ghép lại thành chuỗi bit. Kết quả là một chuỗi nhị phân, decode sang ASCII ra rác, không có tiền tố `grodno`. Loại.

**Thử 3 — Arithmetic coding:** Logits tạo ra một phân phối xác suất. Arithmetic coding dùng phân phối đó để encode data nhị phân — đây là kỹ thuật thực tế trong AI stego. Mình viết decoder nhưng không có tiêu chí dừng rõ ràng và output không verify được. Loại.

**Thử 4 — Huffman/prefix code:** Xây Huffman tree từ top-K token, xem cover text như encoded message. Không tạo được chuỗi có thể verify. Loại.

Tất cả đều thất bại với cùng dãy rank `[41, 62, 1959, ...]`. Mình bắt đầu nghi ngờ không phải hướng giải sai mà là **dãy rank mình đang dùng sai**.

---

## Phần 6: Khoảnh khắc nhận ra — batch ≠ sequential

> Mình nghĩ lại về quá trình encode. Người gửi dùng model để *sinh* từng token — tức là họ chạy một vòng lặp generation, không phải eval batch. Trong vòng lặp đó, **tại mỗi bước, model chỉ nhìn thấy các token đã được sinh ra trước đó**, không nhìn thấy tương lai.
>
> Khi mình eval batch (`llm.eval(prompt + continuation)`), model xử lý toàn bộ chuỗi cùng lúc. Cơ chế Self-Attention trong Transformer cho phép mỗi vị trí "nhìn" sang các vị trí khác. Với causal masking thông thường thì vị trí `i` không nhìn được vị trí `j > i` — nhưng với quantized GGUF và cách `llama-cpp-python` quản lý KV cache, trạng thái nội tại của model khi eval batch và khi generate tuần tự vẫn có thể khác nhau ở mức numerical precision.
>
> Kết luận: mình phải mô phỏng đúng vòng generation: eval prompt → đọc logits → lấy rank của token[0] → feed token[0] → đọc logits mới → lấy rank của token[1] → feed token[1] → tiếp tục.

![So sánh batch evaluation (sai) và sequential evaluation (đúng)](images/batch_vs_sequential.png)

Mình chuyển sang sequential:

```python
llm.reset()
llm.eval(prompt_tokens)           # bước 1: eval prompt, không có continuation

ranks = []
for token_id in continuation_tokens:
    logits = llm.scores[llm.n_tokens - 1]   # logits của vị trí cuối hiện tại
    order = np.argsort(logits)[::-1]
    rank = int(np.where(order == token_id)[0][0])
    ranks.append(rank)
    llm.eval([token_id])           # feed token vào, cập nhật state
```

Kết quả thay đổi hẳn:

```
sequential ranks:
token 'Prepare'  → rank 48
token ' or'      → rank 69
token ' salmon'  → rank 1993
token ' ste'     → rank 76
token 'aim'      → rank 166
token 'all'      → rank 125
token ' stock'   → rank 25
token ','        → rank 0

ranks = [48, 69, 1993, 76, 166, 125, 25, 0]
```

So sánh trực tiếp:

```
sequential: [48, 69, 1993, 76, 166, 125, 25, 0]
batch:       [41, 62, 1959, 75, 155, 135, 26, 0]
```

Hai dãy khác nhau ở mọi vị trí (trừ cuối cùng bằng 0). Đây là lý do tất cả các hướng decode trước đó đều thất bại — mình đang decode từ dữ liệu sai.

---

## Phần 7: Decode dùng flag prefix làm context

Bây giờ mình có dãy rank đúng `[48, 69, 1993, 76, 166, 125, 25, 0]`. Để decode, mình cần một context ban đầu. Đề bài cho flag format `grodno{...}` — đây chính là context.

Tại sao `grodno{` làm context? Vì encoder khi giấu tin cần một "điểm bắt đầu" cho phép decoder biết phải đọc từ đâu. Flag prefix là thứ cả encoder lẫn decoder đều biết trước — nó đóng vai trò shared secret về context ban đầu. Nếu decoder dùng cùng prefix, cùng model, cùng rank → sẽ ra cùng chuỗi token → cùng flag.

Cụ thể, bước decode diễn ra như sau:

1. Tokenize prefix `grodno{` → prompt tokens
2. Eval prompt tokens → model nhớ context "grodno{"
3. Đọc logits → sort theo thứ tự giảm dần → lấy token tại **rank 48** → đó là `st`
4. Feed `st` vào model → model nhớ context "grodno{st"
5. Đọc logits → sort → lấy token tại **rank 69** → đó là `ego`
6. Tiếp tục cho đến hết 8 rank

```python
def decode_from_prefix(llm, prefix, ranks):
    prefix_tokens = llm.tokenize(prefix.encode(), add_bos=False, special=False)
    llm.reset()
    llm.eval(prefix_tokens)

    decoded_tokens = []
    decoded_pieces = []
    for rank in ranks:
        logits = llm.scores[llm.n_tokens - 1]
        order = np.argsort(logits)[::-1]     # sort logits giảm dần
        token_id = int(order[rank])           # lấy token tại vị trí rank
        decoded_tokens.append(token_id)
        decoded_pieces.append(piece(llm, token_id))
        llm.eval([token_id])                  # feed vào để cập nhật context

    flag = llm.detokenize(prefix_tokens + decoded_tokens).decode("utf-8", errors="replace")
    return flag, decoded_pieces
```

---

## Phần 8: Chạy solver và lấy flag

```bash
$ .venv/bin/python solve.py
```

```
prompt: 'A short recipe for a winter vegetable soup:\n'
continuation: 'Prepare or salmon steaimall stock,'
continuation tokens:
   50590 'Prepare'
     476 ' or'
   40320 ' salmon'
    4087 ' ste'
    2640 'aim'
     541 'all'
    5591 ' stock'
      11 ','
ranks: [48, 69, 1993, 76, 166, 125, 25, 0]
decoded pieces: ['st', 'ego', '_can', '_be', '_even', '_like', '_this', '}']
verification ranks: [48, 69, 1993, 76, 166, 125, 25, 0]
match: True
flag: grodno{stego_can_be_even_like_this}
```

![Toàn bộ pipeline từ cover text đến flag](images/full_pipeline.png)

Giải thích dòng `decoded pieces`: 8 rank decode thành 8 token, mỗi token là một subword:

| Rank | Token trong cover text | Token trong flag | Ký tự |
|------|------------------------|------------------|-------|
| 48   | `Prepare`              | `st`             | st    |
| 69   | ` or`                  | `ego`            | ego   |
| 1993 | ` salmon`              | `_can`           | _can  |
| 76   | ` ste`                 | `_be`            | _be   |
| 166  | `aim`                  | `_even`          | _even |
| 125  | `all`                  | `_like`          | _like |
| 25   | ` stock`               | `_this`          | _this |
| 0    | `,`                    | `}`              | }     |

8 token decode ra `stego_can_be_even_like_this}` — 28 ký tự, không phải 8 ký tự.

Dòng `match: True` là bước verification: mình lấy rank của flag body theo prefix `grodno{` bằng sequential eval, ra đúng `[48, 69, 1993, 76, 166, 125, 25, 0]`, khớp với rank từ cover text.

---

## Ghép Flag

```
grodno{stego_can_be_even_like_this}
```

---

## Bài học rút ra

**1. Khi đề bài chỉ định model + revision + runtime, đó là toàn bộ bài toán**
Đây không phải decoration. Logits của GGUF quantized model phụ thuộc vào cách thư viện C++ tính toán. Setup sai phiên bản → rank sai → flag sai. Cài đúng `llama-cpp-python==0.3.16` và tải đúng revision hash là bước không thể bỏ qua.

**2. Batch evaluation và sequential evaluation của LLM không cho cùng rank — đây là dead-end tốn thời gian nhất**
Khi eval batch, model xử lý toàn bộ chuỗi cùng lúc và trạng thái nội tại khác với khi generate tuần tự. Để tái tạo hành vi của encoder, decoder phải chạy sequential: `eval(prompt)` → đọc logits → feed từng token. Nhìn thấy dãy rank có cấu trúc từ batch eval rất dễ bị dẫn sang các hướng sai như ASCII, bitstream, arithmetic coding.

**3. Token rank là kênh giấu tin "vô hình"**
Cover text được tạo bằng model trông như văn bản thường (dù vô nghĩa về nghĩa). Không có byte lạ, không có encoding đặc biệt, không thể phát hiện bằng công cụ thông thường. Dấu hiệu nhận biết: text có ngữ pháp đúng nhưng ý nghĩa hoàn toàn rời rạc, và đề bài nhắc đến model/AI cụ thể.

**4. Flag prefix là shared context để decode**
Cả encoder lẫn decoder cùng biết flag format. Encoder giấu tin dưới context của prompt, decoder giải mã dưới context của prefix `grodno{`. Cùng rank + cùng model + context thích hợp → ra cùng chuỗi token.

**5. Đừng đồng nhất "N rank = N ký tự"**
Subword tokenizer gộp nhiều ký tự thành một token. 8 rank trong bài này decode ra 28 ký tự vì mỗi token như `_even`, `_like`, `_this` chứa nhiều ký tự.

---

## Tài liệu tham khảo

- HuggingFace model: `Qwen/Qwen2.5-0.5B-Instruct-GGUF`
- Revision: `9217f5db79a29953eb74d5343926648285ec7e67`
- Runtime: `llama-cpp-python==0.3.16`
- Solver: `solve.py`
