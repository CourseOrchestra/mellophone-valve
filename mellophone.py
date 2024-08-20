# coding: utf-8
import json
import logging
from dataclasses import dataclass
from http import HTTPStatus
from uuid import uuid4

import requests
import xmltodict

from src.utils.case_conversion import camel_to_snake_case


class ForbiddenError(Exception):
    pass


class NotFoundError(Exception):
    pass


class IncorrectMellophoneUrlError(Exception):
    pass


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def xml2json(xml, key='user') -> dict[str, str]:
    res = xmltodict.parse(xml)['user']

    for key in list(res.keys())[:]:
        res[key.lstrip('@').lower()] = res.pop(key)

    return res


@dataclass
class Mellophone:
    """Класс для работы с mellophone
    Подробное описание сервлетов указано в https://courseorchestra.github.io/mellophone2/
    """
    _base_url: str
    set_settings_token: str
    user_manage_token: str
    session_id: str = None

    def __send_request(self, url, method="get", data=None):
        url = f'{self._base_url}{url}'
        if method == 'post':
            res = {}
            for key in data.keys():
                res[f'@{key}'] = data[key]
            data = xmltodict.unparse({'user': res})
            response = requests.post(url, data=data)
        else:
            response = requests.get(url)
        if response.status_code == HTTPStatus.FORBIDDEN:
            raise ForbiddenError(response.text)
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise NotFoundError(response.text)
        response.raise_for_status()

        return response.text

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
        ses_id = ses_id or self.session_id or str(uuid4())
        url = f'/login?sesid={ses_id}&login={login}&pwd={password}'

        if gp is not None:
            url += '&gp={}'.format(gp)

        if ip:
            url += '&ip={}'.format(ip)

        self.__send_request(url)

        self.session_id = ses_id

    def logout(self, ses_id=None):
        """Разаутентифицирует указанную сессию приложения или текущую
        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})
        """
        url = '/logout?&sesid={}'.format(ses_id or self.session_id)

        self.__send_request(url)

    def create_user(self, user):
        url = f'/user/create?token={self.user_manage_token}'
        if 'password' in user:
            user['pwd'] = user.pop('password')
        return self.__send_request(url, method="post", data=user)

    def update_user(self, sid, token, user):

        url = f'/user/{sid}?token={token}'
        user = json.dumps(user)
        return self.__send_request(url, method="post", data=user)

    def is_authenticated(self, ses_id=None):
        """Возвращает информацию об аутентифицированном пользователе, если сессия аутентифицирована
        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})
        Returns:
            json -- информация о пользователе
        """
        url = f'/isauthenticated?sesid={ses_id or self.session_id}'
        try:
            response = self.__send_request(url)
        except ForbiddenError:
            return False
        else:
            return xml2json(response)

    def change_app_ses_id(self, new_ses_id, ses_id=None):
        """Изменяет сессию.
            [не уверена, что корректно работает на стороне меллофона]
        Arguments:
            new_ses_id {str} -- новая сессия
        Keyword Arguments:
            old_ses_id {str} -- старая сессия (по умолчанию текущая) (default: {None})
        """
        url = f'/changeappsesid?oldsesid={ses_id or self.session_id}&newsesid={new_ses_id}'
        self.__send_request(url)

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
        url = f'/checkname?sesid={ses_id or self.session_id}&name={name}'
        response = self.__send_request(url)
        return xml2json(response)

    def import_gp(self):
        """
        Returns:
            list -- список групп провайдеров
        """
        url = '/importgroupsproviders'
        response = self.__send_request(url)
        return response.split()

    def change_pwd(self, old_pwd, new_pwd, ses_id=None):
        """Изменяет пароль пользователя по sesid
            [дополнительная проверка по паролю]
        Arguments:
            old_pwd {str} -- Старый пароль
            new_pwd {str} -- Новый пароль
        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})
        Returns:
            [type] -- [description]
        """
        url = f'/changepwd?sesid={ses_id or self.session_id}&oldpwd={old_pwd}&newpwd={new_pwd}'
        self.__send_request(url)

    def change_user_pwd(self, username, old_pwd, new_pwd, ses_id=None):
        """Изменяет пароль пользователя по username (доступно только админам)
        Arguments:
            username {str} -- Логин пользователя, которому нужно изменить пароль
            old_pwd {str} -- Старый пароль
            new_pwd {str} -- Новый пароль
        Keyword Arguments:
            ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})
        Returns:
            [type] -- [description]
        """
        url = f'/changeuserpwd?sesid={ses_id or self.session_id}&oldpwd={old_pwd}&newpwd={new_pwd}&username={username}'
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
        return xml2json(response)

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

        response = self.__send_request(url)

        return xml2json(response)

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
