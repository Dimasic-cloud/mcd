# импортируем зависимости для создания сервера и функций обработки сообщений
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask import Flask, request, jsonify

app = Flask(__name__)  # объект нашего сервера

@app.route('/encryption', methods=['POST'])  # дикаратор для создания маршрутов
def encryption():  # функция связанная с маршрутом выше. она шифрует сообщения с помощью симитричного ключа
    data =request.get_json()  # получаем данные из POST запроса в формате json

    if not data or 'text' not in data:  # проверяем данные на соответствие и возвращаем ошибку, если данные оказались не в верном виде
        return jsonify({"status": "error", "message": "Missing 'text' field in JSON"}), 400

    plain_text = data['text']  # текст, который нужно зашифровать копируем в переменную для удобства работы

    try:  # оброботчик исключений
        key = Fernet.generate_key()  # генирируем 32-байтный ключ для шифрования и расшифровки текста
        encrypter = Fernet(key)

        # сначала шифруем текст, а затем переводим зашифрованный текст с кючём в другой вид, для хранения в json
        cypher_text = encrypter.encrypt(plain_text.encode())
        cypher_text_b64 = urlsafe_b64encode(cypher_text).decode()
        key_b64 = urlsafe_b64encode(key).decode()

        # возвращаем сообщение о том, что прошло всё удачно и так же зашифрованный текст с ключём всё в формате json
        return jsonify({
            "status": "success!",
            "encrypted_text": cypher_text_b64,
            "key": key_b64
        })
    
    # обрабатываем исключение, если при шифровании получили ошибку
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/decryption', methods=['POST'])
def decryption():  # функция для расшифровки текста
    data = request.get_json()

    if not data or "encrypted_text" not  in data or "key" not in data:
        return jsonify({"status": "error", "message": "Missing 'encrypted_text' and 'key' field in JSON"}), 400
    
    try:
        # блок кода посвящённый расшифровки зашифрованного ранее текста с ключём
        encrypted_text = urlsafe_b64decode(data['encrypted_text'].encode())
        key = urlsafe_b64decode(data['key'].encode())
        decrypter = Fernet(key)
        plain_text = decrypter.decrypt(encrypted_text).decode()
        return jsonify({"status": "success", "text": plain_text})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# условие для запуска только из изходного файла
if __name__ == "__main__":
    app.run(debug=True)  # стартер для начала работы сервера