Cấu trúc file 'public_key.txt'
- Mỗi dòng là tên || n = pq (khoá công khai mặc định là e = 65537 nên không cần lưu giá trị này)
Cấu trúc file 'private_key.txt'
- Mỗi dòng là tên || khoá bí mật d || số nguyên tố p

(Giả sử toàn bộ thành viên trong hệ thống đều xài RSA-1024 -> b = 1028)

Kích thước của ring là r = 8 (lưu trong file ring_sign.h)

Mặc định index của người kí s = 8

Khoá công khai là 1 giá trị n, không có e vì e mặc định là 65537

Hàm mã khoá E = k xor m

Câu lệnh biên dịch: g++ sp_func.h sp_func.cpp sha256.h sha256.cpp ring_sign.h ring_sign.cpp ring_verify.cpp ring_verify.h main.cpp -lcrypto