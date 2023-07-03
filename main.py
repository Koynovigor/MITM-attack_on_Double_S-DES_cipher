# coding=windows-1251
import random

initial_permutation = [2, 6, 3, 1, 4, 8, 5, 7]
final_permutation = [4, 1, 3, 5, 7, 2, 8, 6]

P_block_of_direct_permutations = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P_block_compression = [6, 3, 7, 4, 8, 5, 10, 9]

P_block_expansion = [4, 1, 2, 3, 2, 3, 4, 1]

S_block1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S_block2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

Direct_P_block = [2, 4, 3, 1]

def shift(lst, steps):
    if steps < 0:
        steps = abs(steps)
        for i in range(steps):
            lst.append(lst.pop(0))
    else:
        for i in range(steps):
            lst.insert(0, lst.pop())
    return lst

def f(block, key):
    # Расширяем блок до 8 бит
    block = [block[i - 1] for i in P_block_expansion]

    # XOR с ключом
    block_xor = [block[i] ^ key[i] for i in range(8)]

    # Перестановка с помощью S-блоков
    # разделяем блок на 2 части
    for_s1 = block_xor[:4]
    for_s2 = block_xor[4:]

    # Ищем в таблице перестановок нужное значение для левой части
    a = 2 * for_s1[0] + for_s1[3]
    b = 2 * for_s1[1] + for_s1[2]
    s1 = S_block1[a][b]
    # Преобразуем в двоичное число
    s1 = [s1 // 2, s1 % 2]
    
    # Ищем в таблице перестановок нужное значение для правой части
    a = 2 * for_s2[0] + for_s2[3]
    b = 2 * for_s2[1] + for_s2[2]
    s2 = S_block2[a][b]
    # Преобразуем в двоичное число
    s2 = [s2 // 2, s2 % 2]

    res = s1 + s2
    return [res[i - 1] for i in Direct_P_block]

def permutation(input, table):
    return [input[i - 1] for i in table]

def s_des_encrypt(plain_text, key, t = True):
    # Начальная престановка
    ptext = permutation(plain_text, initial_permutation)

    # Делим исходный блок на 2 части
    Li = ptext[:4]
    Ri = ptext[4:]

    # Прямая перестановка
    key10 = permutation(key, P_block_of_direct_permutations)

    # Делим ключ на 2 части
    Lkey = key10[:5]
    Rkey = key10[5:]

    # # Генерация ключа для первого раунда
    # Выполянем левый циклический на 1 сдвиг для правой и левой части ключа
    Lkey = shift(Lkey, -1)
    Rkey = shift(Rkey, -1)

    # Объеденяем левыю и правую части
    key10 = Lkey + Rkey

    # Сжимаем ключ до 8 бит и получаем ключ для первого раунда шифрования
    key_for_r1 = permutation(key10, P_block_compression)

    # # Генерация ключа для второго раунда раунда
    # Выполянем левый циклический на 2 сдвиг для правой и левой части ключа
    Lkey = shift(Lkey, -2)
    Rkey = shift(Rkey, -2)

    # Объеденяем левыю и правую части
    key10 = Lkey + Rkey

    # Сжимаем ключ до 8 бит и получаем ключ для второго раунда шифрования
    key_for_r2 = permutation(key10, P_block_compression)

    if t == False:
        key_for_r1, key_for_r2 = key_for_r2, key_for_r1

    # # Первй раунд шифрования
    f_des = f(Ri, key_for_r1)

    # XOR с левой частью
    r1 = [f_des[i] ^ Li[i] for i in range(4)]
    l1 = Ri

    # # Второй раунд шифрования
    f_des = f(r1, key_for_r2)
    
    # XOR с левой частью
    l2 = [f_des[i] ^ l1[i] for i in range(4)]
    r2 = r1

    res = l2 + r2
    # Конечная перестановка
    return permutation(res, final_permutation)

def s_des_decrypt(ciphertext, key):
    return s_des_encrypt(ciphertext, key, False)

def gen(num, rand = -1):
    if rand == -1:
        a = [int(bit) for bit in bin(random.randrange(2**num))[2:]]
        a = [0 for i in range(0, num - len(a))] + a
    else:
        a = [int(bit) for bit in bin(rand)[2:]]
        a = [0 for i in range(0, num - len(a))] + a
    return a

def to_str(list):
    return "".join(str(x) for x in list)

msg = gen(8)
k1 = gen(10)
k2 = gen(10)
ciphertext = s_des_encrypt(s_des_encrypt(msg, k1), k2)

eMsg = {}
dMsg = {}
# Строим таблицу "незашифрованный текст - соответствующий ему зашифрованный текст" 
for i in range(1024):
    key = gen(10, i)
    s = to_str(key)
    eMsg[s] = to_str(s_des_encrypt(msg, key))
    dMsg[s] = to_str(s_des_decrypt(ciphertext, key))

# Ищем подходящие пары
possible_pair = []
for x in eMsg:
    for y in dMsg:
        if eMsg.get(x) == dMsg.get(y):
            possible_pair.append([x, y])

# Перебираем все пары
while len(possible_pair) != 1:
    msg_tmp = gen(8)
    d_s_des = s_des_encrypt(s_des_encrypt(msg_tmp, k1), k2)
    key_tmp = []
    for x in possible_pair:
        k1_tmp = [int(bit) for bit in x[0]]
        k2_tmp = [int(bit) for bit in x[1]]
        res_enc = s_des_encrypt(msg_tmp, k1_tmp)
        res_dec = s_des_decrypt(d_s_des, k2_tmp)
        if res_enc == res_dec:
            key_tmp.append(x)
    possible_pair = key_tmp

print("Найденные ключи: k1: %s\t k2: %s"%(possible_pair[0][0], possible_pair[0][1]))
print("Исходные ключи:  k1: %s\t k2: %s"%(to_str(k1), to_str(k2)))
