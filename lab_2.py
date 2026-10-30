import hashlib


# 64 константы раундов SHA256
K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

# Начальные значения хеша
INITIAL_HASH = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

MASK = 0xFFFFFFFF


def rotate_right(value, bits):
    """Циклический сдвиг 32битного числа вправо"""
    return ((value >> bits) | (value << (32 - bits))) & MASK


def sha256(message):
    """Вычисляет SHA-256 без hashlib"""
    if isinstance(message, str):
        message = message.encode("utf-8")

    padded = bytearray(message)
    original_bit_length = len(message) * 8
    padded.append(0x80)

    while len(padded) % 64 != 56:
        padded.append(0)

    # добавляем исходную длину сообщения как 64битное число
    padded.extend(original_bit_length.to_bytes(8, byteorder="big"))

    hash_values = INITIAL_HASH.copy()

    # обрабатываем сообщение блоками по 64 байта
    for block_start in range(0, len(padded), 64):
        block = padded[block_start:block_start + 64]

        # первые 16 слов расписания сообщения по 32 бита
        words = [
            int.from_bytes(block[i:i + 4], byteorder="big")
            for i in range(0, 64, 4)
        ]

        # расширение расписания до 64 слов
        for i in range(16, 64):
            s0 = (
                rotate_right(words[i - 15], 7)
                ^ rotate_right(words[i - 15], 18)
                ^ (words[i - 15] >> 3)
            )
            s1 = (
                rotate_right(words[i - 2], 17)
                ^ rotate_right(words[i - 2], 19)
                ^ (words[i - 2] >> 10)
            )
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & MASK)

        a, b, c, d, e, f, g, h = hash_values

        # 64 раунда преобразования состояния
        for i in range(64):
            sum1 = (
                rotate_right(e, 6)
                ^ rotate_right(e, 11)
                ^ rotate_right(e, 25)
            )
            choice = (e & f) ^ ((~e) & g)
            temp1 = (h + sum1 + choice + K[i] + words[i]) & MASK

            sum0 = (
                rotate_right(a, 2)
                ^ rotate_right(a, 13)
                ^ rotate_right(a, 22)
            )
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sum0 + majority) & MASK

            h = g
            g = f
            f = e
            e = (d + temp1) & MASK
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK

        # прибавляем результат блока к текущим значениям хеша
        updated = [a, b, c, d, e, f, g, h]
        hash_values = [
            (old + new) & MASK
            for old, new in zip(hash_values, updated)
        ]

    return "".join(f"{value:08x}" for value in hash_values)


def check_message(text):
    """Сравнивает собственную реализацию с hashlib"""
    own_hash = sha256(text)
    library_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    print(f"Сообщение: {text!r}")
    print(f"Собственная реализация: {own_hash}")
    print(f"hashlib.sha256():      {library_hash}")
    print(f"Совпадение: {own_hash == library_hash}")
    print()


if __name__ == "__main__":
    check_message("")
    check_message("abc")
    check_message("строка для проверки")
