# -*- coding: utf-8 -*-
##############################################################################
# Copyright 2018-present, iEXBase, Inc.
# All rights reserved.
#
# This source code is licensed under the license found in the
# LICENSE file in the root directory of this source tree.
##############################################################################

import base58
import math

from tronapi.crypto import utils
from tronapi.providers import HttpProvider


class Tron:
    def __init__(self, full_node, solidity_node=None, event_server=None, private_key=None):
        if isinstance(full_node, str):
            full_node = HttpProvider(full_node)

        if isinstance(solidity_node, str):
            solidity_node = HttpProvider(solidity_node)

        self.full_node = full_node
        self.solidity_node = solidity_node
        self.event_server = event_server

        if private_key:
            self.private_key = private_key

    @staticmethod
    def is_valid_provider(provider):
        """Проверка провайдера

        Args:
            provider(str): Провайдер

        Returns:
           True в случае успеха, False в противном случае.

        """
        return isinstance(provider, HttpProvider)

    def get_current_block(self):
        """Последний номер блока"""
        return self.full_node.request('/wallet/getnowblock')

    def get_block(self, block=None):
        """Получаем детали блока с помощью HashString или blockNumber

        Args:
            block (int | str): Номер или Хэш блока

        """
        if block is None:
            exit('No block identifier provided')

        if block == 'latest':
            return self.get_current_block()

        if type(block) is str:
            return self.get_block_by_hash(block)

        return self.get_block_by_number(block)

    def get_block_by_hash(self, hash_block):
        """Получаем детали блока по хэшу

        Args:
            hash_block (str): Хэш блока

        """
        return self.full_node.request('/wallet/getblockbyid', {
            'value': hash_block
        })

    def get_block_by_number(self, block_id):
        """Получаем детали блока по номеру

        Args:
            block_id (int): Номер блока

        """
        if not utils.is_integer(block_id) or block_id < 0:
            exit('Invalid block number provided')

        return self.full_node.request('/wallet/getblockbynum', {
            'num': int(block_id)
        })

    def get_block_transaction_count(self, block=None):
        """Получаем детали блока по номеру

        Args:
            block (int | str): Номер или Хэш блока

        """
        transaction = self.get_block(block)['transactions']

        if transaction == 0:
            return 0

        return len(transaction)

    def get_transaction_from_block(self, block=None, index=0):
        """Получаем детали транзакции из Блока

        Args:
            block (int | str): Номер или Хэш блока
            index (int) Позиция транзакции

        """
        if not utils.is_integer(index) or index < 0:
            exit('Invalid transaction index provided')

        transactions = self.get_block(block)['transactions']

        if not transactions or len(transactions) < index:
            exit('Transaction not found in block')

        return transactions[index]

    def get_transaction(self, transaction_id):
        """Получаем информацию о транзакции по TxID

        Args:
            transaction_id (str): Хэш транзакции

        """
        response: object = self.full_node.request('/wallet/gettransactionbyid', {
            'value': transaction_id
        }, 'post')

        if not response:
            exit('Transaction not found')

        return response

    def get_account(self, address):
        """Информация об аккаунте

        Args:
            address (str): Адрес учетной записи

        """
        return self.full_node.request('/wallet/getaccount', {
            'address': self.to_hex(address)
        }, 'post')

    def get_balance(self, address):
        """Получение баланса

        Args:
            address (str): Адрес учетной записи

        """
        response = self.get_account(address)

        return response['balance']

    def get_band_width(self, address):
        """Выбирает доступную пропускную способность для определенной учетной записи

        Args:
            address (str): Адрес учетной записи

        """
        return self.full_node.request('/wallet/getaccountnet', {
            'address': self.to_hex(address)
        })

    def get_transaction_count(self):
        """Получаем общий счетчик транзакций

        Note: Считывается все транзакции блокчейн сети Tron

        Examples:
            >>> tron.get_transaction_count()

        Returns:
            Получение результата в виде строки

        """
        response = self.full_node.request('/wallet/totaltransaction')

        return response['num']

    def send_transaction(self, from_address, to_address, amount):
        """Отправляем транзакцию в Blockchain

        Args:
            from_address (str): Адрес отправителя
            to_address (str): Адрес получателя
            amount (float): Сумма отправки

        Returns:
            Возвращает детали отправляемой транзакции
            [result=1] - Успешно отправлено

        """
        if not self.private_key:
            exit('Missing private key')

        transaction = self._create_transaction(from_address, to_address, amount)
        sign = self._sign_transaction(transaction)
        response = self._send_raw_transaction(sign)

        result = dict(sign)
        result.update(response)

        return result

    def _create_transaction(self, from_address, to_address, amount):
        """Создаем неподписанную транзакцию

        Args:
            from_address (str): Адрес отправителя
            to_address (str): Адрес получателя
            amount (float): Сумма отправки

        Returns:
            Возвращает неподписанную транзакцию

        """
        return self.full_node.request('/wallet/createtransaction', {
            'to_address': self.to_hex(to_address),
            'owner_address': self.to_hex(from_address),
            'amount': self.to_tron(amount)
        }, 'post')

    def _sign_transaction(self, transaction):
        """Подписываем транзакцию

        Note: Транзакции подписываются только с использованием приватного ключа

        Args:
            transaction (object): Детали транзакции

        """
        if 'signature' in transaction:
            exit('Transaction is already signed')

        return self.full_node.request('/wallet/gettransactionsign', {
            'transaction': transaction,
            'privateKey': self.private_key
        }, 'post')

    def _send_raw_transaction(self, signed):
        """Отправляем подписанную транзакцию

        Note: Если транзакция подписана то отправляем в сеть tron

        Args:
            signed (object): Детали подписанной транзакции

        """
        if not type({}) is dict:
            exit('Invalid transaction provided')

        if 'signature' not in signed:
            exit('Transaction is not signed')

        return self.full_node.request('/wallet/broadcasttransaction', signed, 'post')

    def update_account(self, address, name):
        """Изменить имя учетной записи

        Note: Имя пользователя разрешается редактировать только один раз

        Args:
            address (str): Адрес учетной записи
            name (str): Новое имя

        """
        transaction = self.full_node.request('/wallet/updateaccount', {
            'account_name': self.string_utf8_to_hex(name),
            'owner_address': self.to_hex(address)
        })

        sign = self._sign_transaction(transaction)
        response = self._send_raw_transaction(sign)

        return response

    def register_account(self, address, new_account_address):
        """Регистрация новой учетной записи в сети

        Args:
            address (str): Адрес учетной записи
            new_account_address (str): Новый адрес

        """
        return self.full_node.request('/wallet/createaccount', {
            'owner_address': self.to_hex(address),
            'account_address': self.to_hex(new_account_address)
        }, 'post')

    def apply_for_super_representative(self, address, url):
        """Выдвигать кандидатуру супер представителя

        Note: Применяется, чтобы стать супер представителем. Стоимость 9999 TRX.

        Args:
            address (str): Адрес учетной записи
            url (str): Адрес сайта

        """
        return self.full_node.request('/wallet/createwitness', {
            'owner_address': self.to_hex(address),
            'url': self.string_utf8_to_hex(url)
        }, 'post')

    def list_nodes(self):
        """Список доступных нодов"""
        return self.full_node.request('/wallet/listnodes')

    def get_tokens_issued_by_address(self, address):
        """Попытки найти токен с адресом учетной записи, который его выпустил

        Args:
            address (str): Адрес учетной записи

        """
        return self.full_node.request('/wallet/getassetissuebyaccount', {
            'address': self.to_hex(address)
        }, 'post')

    def get_token_from_id(self, token_id):
        """Попытки найти токен по имени

        Args:
            token_id (str): ID токена

        """
        return self.full_node.request('/wallet/getassetissuebyname', {
            'value': self.string_utf8_to_hex(token_id)
        })

    def get_block_range(self, start, end):
        """Получаем список блоков из определенного диапазона

        Args:
            start (int): Начало
            end (int): Конец

        """
        if not utils.is_integer(start) or start < 0:
            exit('Invalid start of range provided')

        if not utils.is_integer(end) or end <= start:
            exit('Invalid end of range provided')

        return self.full_node.request('/wallet/getblockbylimitnext', {
            'startNum': int(start),
            'endNum': int(end) + 1
        }, 'post')['block']

    def get_latest_blocks(self, limit=1):
        """Получаем список последних блоков

        Args:
            limit (int): Количество блоков

        """
        if not utils.is_integer(limit) or limit <= 0:
            exit('Invalid limit provided')

        return self.full_node.request('/wallet/getblockbylatestnum', {
            'limit': limit
        }, 'post')['block']

    def list_super_representatives(self):
        """Получаем список суперпредставителей

        Examples:
            >>> tron.list_super_representatives()

        """
        return self.full_node.request('/wallet/listwitnesses')['witnesses']

    def list_tokens(self, limit=0, offset=0):
        """Получаем список выпущенных токенов

        Args:
            limit (int): Количество токенов на странице
            offset (int): Страницы

        """
        if not utils.is_integer(limit) or (limit and offset < 1):
            exit('Invalid limit provided')

        if not utils.is_integer(offset) or offset < 0:
            exit('Invalid offset provided')

        if not limit:
            return self.full_node.request('/wallet/getassetissuelist')['assetIssue']

        return self.full_node.request('/wallet/getpaginatedassetissuelist', {
            'limit': int(limit),
            'offset': int(offset)
        }, 'post')

    def time_until_next_vote_cycle(self):
        """Возвращает время в миллисекундах до следующего подсчета голосов SR"""
        num = self.full_node.request('/wallet/getnextmaintenancetime')['num']

        if num == -1:
            exit('Failed to get time until next vote cycle')

        return math.floor(num / 1000)

    def validate_address(self, address, hex=False):
        """Проверка адресов на действительность

        Args:
            address (str): Адрес учетной записи
            hex (bool): Формат адреса

        """
        if hex:
            address = self.to_hex(address)

        return self.full_node.request('/wallet/validateaddress', {
            'address': address
        }, 'post')

    def generate_address(self):
        """Генерация нового адреса"""
        return self.full_node.request('/wallet/generateaddress')

    @staticmethod
    def string_utf8_to_hex(name):
        """ Преобразование строки в формат Hex

        Args:
            name (str): Строка

        """
        return bytes(name, encoding='utf-8').hex()

    @staticmethod
    def to_tron(amount):
        """Преобразовываем сумму в формат Tron

        Args:
            amount (float): Сумма

        """
        return abs(amount) * pow(10, 6)

    @staticmethod
    def from_tron(amount):
        """Преобразовываем сумму из формата Tron

        Args:
            amount (int): Сумма

        """
        return abs(amount) / pow(10, 6)

    @staticmethod
    def to_hex(address):
        """Получить адресную запись hexString

        Args:
            address (str): Строки, которые необходимо зашифровать

        """
        return base58.b58decode_check(address).hex().upper()

    @staticmethod
    def from_hex(address):
        """Отменить шестнадцатеричную строку

        Args:
            address (str): шестнадцатеричная строка

        """
        return base58.b58encode_check(bytes.fromhex(address))

    def is_connected(self):
        """Проверка всех подключенных нодов"""
        full_node = False
        solidity_node = False

        if self.full_node:
            full_node = self.full_node.is_connected()

        if self.solidity_node:
            solidity_node = self.solidity_node.is_connected()

        return {
            'fullNode': full_node,
            'solidityNode': solidity_node
        }