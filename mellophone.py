# coding: utf-8

import xmltodict
import requests

from http import HTTPStatus

from exceptions import ForbiddenError, NotFoundError, IncorrectMellophoneUrlError
from decorators import default_sesid


class Mellophone:
    """Класс для работы с mellophone
    Подробное описание сервлетов указано в https://corchestra.ru/wiki/index.php?title=Mellophone
    """

    def __init__(self, base_url, session_id=None):
        """

        Arguments:
            base_url {str} -- [Базовый адрес меллофона]

        Keyword Arguments:
            session_id {str} -- [Можно передать ид сессии, полученной извне] (default: {None})
        """
        self.session_id = session_id
        self._base_url = base_url.rstrip('/')
        if 'Mellophone запущен' not in self.__send_request(''):
            raise IncorrectMellophoneUrlError


    def __send_request(self, url):
        url = f'{self._base_url}/{url}'
        response = requests.get(url)
        if response.status_code == HTTPStatus.FORBIDDEN:
            raise ForbiddenError
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise NotFoundError
        response.raise_for_status()
        return response.text

    @default_sesid
    def login(self, login, password, ses_id=None, gp=None, ip=None):
        """Аутентифицирует сессию;
            Если пара "логин-пароль" аутентифицирует сессию приложения ses_id;
            Если пара "логин-пароль" неверна, выкидывает Forbidden

        Arguments:
            login {str} -- Логин пользователя
            password {str} -- Пароль пользователя

        Keyword Arguments:
            ses_id {str} -- Идентификатор сессии (default: {None})
            gp {str} -- Группа провайдеров (когда меллофон подключен к нескольким источникам данных) (default: {None})
            ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})
        """
        url = '/login?&sesid={}&login={}&pwd={}'.format(
            ses_id, login, password)

        if gp is not None:
            url += '&gp={}'.format(gp)

        if ip:
            url += '&ip={}'.format(ip)

        self.__send_request(url)

    @default_sesid
    def logout(self, ses_id=None):
        """Разаутентифицирует указанную сессию приложения или текущую

        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})
        """
        url = '/logout?&sesid={}'.format(ses_id)

        self.__send_request(url)

    @default_sesid
    def is_authenticated(self, ses_id=None):
        """Возвращает информацию об аутентифицированном пользователе, если сессия аутентифицирована

        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})

        Returns:
            json -- информация о пользователе
        """
        url = '/isauthenticated?sesid={}'.format(ses_id)
        try:
            response = self.__send_request(url)
        except ForbiddenError:
            return False
        else:
            return xmltodict.parse(response)

    @default_sesid
    def change_app_ses_id(self, new_ses_id, ses_id=None):
        """Изменяет сессию. 
            [не уверена, что корректно работает на стороне меллофона]

        Arguments:
            new_ses_id {str} -- новая сессия

        Keyword Arguments:
            old_ses_id {str} -- старая сессия (по умолчанию текущая) (default: {None})
        """
        url = '/changeappsesid?oldsesid={}&newsesid={}'.format(
            ses_id, new_ses_id)
        self.__send_request(url)

    @default_sesid
    def check_name(self, name, ses_id=None):
        """Возвращает информацию о пользователе name 
            [любой аутентифицированный пользователь может получить инфу о любом другом пользователе]

        Arguments:
            name {str} -- Имя пользователя

        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})

        Returns:
            json -- информация о пользователе
        """
        url = '/checkname?sesid={}&name={}'.format(ses_id, name)
        response = self.__send_request(url)
        return xmltodict.parse(response)

    def import_gp(self):
        """
        Returns:
            list -- список групп провайдеров
        """
        url = '/importgroupsproviders'
        response = self.__send_request(url)
        return response.split()

    @default_sesid
    def change_pwd(self, old_pwd, new_pwd, ses_id=None):
        """Изменяет пароль пользователя по sesid 
            [дополнительная проверка по паролю]

        Arguments:
            old_pwd {str} -- Старый пароли
            new_pwd {str} -- Новый пароль

        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})

        Returns:
            [type] -- [description]
        """
        url = '/changepwd?sesid={}&oldpwd={}&newpwd={}'.format(
            ses_id, old_pwd, new_pwd)
        self.__send_request(url)

    def check_credentials(self, login, password, gp=None, ip=None):
        """Возвращает информацию о пользователе, если пара логин-пароль верна

        Arguments:
            login {str} -- Логин
            password {str} -- Пароль

        Keyword Arguments:
            gp {str} -- Группа провайдеров (default: {None})
            ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})

        Returns:
            json -- Информация о пользователе
        """
        url = '/checkcredentials?login={}&pwd={}'.format(login, password)

        if gp is not None:
            url += '&gp={}'.format(gp)

        if ip:
            url += '&ip={}'.format(ip)

        response = self.__send_request(url)
        return xmltodict.parse(response)

    def get_provider_list(self, login, password, gp=None, ip=None):
        """Возвращает информацию о провайдерах с группой gp

        Arguments:
            login {str} -- Пользователь, под которым можно получить группу провайдеров
            password {str} -- Пароль пользователя, под которым можно получить группу провайдеров

        Keyword Arguments:
            gp {str} -- Группа провайдеров (default: {None})
            ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})

        Returns:
            list -- Список провайдеров
        """
        url = '/getproviderlist?login={}&pwd={}'.format(login, password)

        if gp is not None:
            url += '&gp={}'.format(gp)

        if ip:
            url += '&ip={}'.format(ip)

        return xmltodict.parse(self.__send_request(url))['providers']

    def get_user_list(self, token, gp, ip=None, pid=None):
        """Возвращает информацию о пользователях провайдера

        Arguments:
            token {str} -- Токен безопасности
            gp {str} -- Группа провайдеров

        Keyword Arguments:
            ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})
            pid {str} -- идентификатор провайдера (default: {None})

        Returns:
            list -- Список пользователей провайдера
        """
        url = '/getuserlist?token={}&gp={}'.format(token, gp)

        if ip:
            url += '&ip={}'.format(ip)

        if pid:
            url += '&ip={}'.format(ip)

        return self.__send_request(url)

    def set_settings(self, token, lockout_time=None, login_attempts_allowed=None):
        """Изменение настроек меллофона

        Arguments:
            token {str} -- Токен безопасности

        Keyword Arguments:
            lockouttime {int} -- время в минутах, на которое будет блокироваться пользователь (default: {None})
            loginattemptsallowed {str} -- разрешенное количество неудачных попыток ввода пароля (default: {None})

        Returns:
            [type] -- [description]
        """
        url = '/setsettings?token={}'.format(token)
        if lockout_time:
            url += '&lockouttime={}'.format(lockout_time)

        if login_attempts_allowed:
            url += '&loginattemptsallowed={}'.format(login_attempts_allowed)
        self.__send_request(url)
