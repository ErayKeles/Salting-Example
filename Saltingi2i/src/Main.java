import hashlib
import os
import json

# Salt oluşturma fonksiyonu
def generate_salt():
        # 16 baytlık güvenli bir salt oluştur
    return os.urandom(16)

# Şifreyi hash'leme fonksiyonu
def hash_password(password, salt):
        # Şifre ve salt'ı birleştirip SHA-256 algoritması ile hash'liyoruz
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hash_obj

# Şifre doğrulama fonksiyonu
def verify_password(stored_password, salt, provided_password):
        # Girilen şifreyi verilen salt ile hash'le
hash_obj = hash_password(provided_password, salt)
    # Hash değerlerini karşılaştır
    return hash_obj == stored_password

# Hash ve salt'ı JSON dosyasına kaydetme
def save_password(hash_value, salt, filename="stored_password.json"):
with open(filename, 'w') as file:
data = {
        "hash": hash_value.hex(),
            "salt": salt.hex()
        }
                json.dump(data, file)
print("Hash ve salt başarıyla kaydedildi.")

# Kaydedilen hash ve salt'ı JSON dosyasından okuma
def load_password(filename="stored_password.json"):
with open(filename, 'r') as file:
data = json.load(file)
        return bytes.fromhex(data["hash"]), bytes.fromhex(data["salt"])

# Ana program
def main():
        # Şifreyi alma
password = input("Lütfen şifrenizi girin: ")

    # Salt oluşturma ve şifreyi hash'leme
salt = generate_salt()
hashed_password = hash_password(password, salt)

    # Şifreyi kaydetme
save_password(hashed_password, salt)

    # Tekrar doğrulama için şifre iste
        provided_password = input("\nŞifrenizi tekrar girin (doğrulama): ")

    # Kaydedilmiş hash ve salt'ı JSON'dan yükle
stored_hash, stored_salt = load_password()

    # Şifre doğrulama
    if verify_password(stored_hash, stored_salt, provided_password):
print("Şifre doğrulandı, giriş başarılı!")
    else:
print("Şifreler eşleşmiyor, lütfen tekrar deneyin.")

# Programı çalıştır
if __name__ == "__main__":
main()
