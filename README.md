Module mellophone
=================

Classes
-------

`Mellophone(base_url, session_id=None)`
:   Класс для работы с mellophone
    Подробное описание сервлетов указано в https://corchestra.ru/wiki/index.php?title=Mellophone

Arguments:
    base_url {str} -- [Базовый адрес меллофона]

Keyword Arguments:
    session_id {str} -- [Можно передать ид сессии, полученной извне] (default: {None})

### Methods

`change_app_ses_id(self, new_ses_id, ses_id=None)`
:   Изменяет сессию.
        [не уверена, что корректно работает на стороне меллофона]

    Arguments:
        new_ses_id {str} -- новая сессия

    Keyword Arguments:
        old_ses_id {str} -- старая сессия (по умолчанию текущая) (default: {None})

`change_pwd(self, old_pwd, new_pwd, ses_id=None)`
:   Изменяет пароль пользователя по sesid
        [дополнительная проверка по паролю]

    Arguments:
        old_pwd {str} -- Старый пароли
        new_pwd {str} -- Новый пароль

    Keyword Arguments:
        ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})

    Returns:
        [type] -- [description]

`check_credentials(self, login, password, gp=None, ip=None)`
:   Возвращает информацию о пользователе, если пара логин-пароль верна

    Arguments:
        login {str} -- Логин
        password {str} -- Пароль

    Keyword Arguments:
        gp {str} -- Группа провайдеров (default: {None})
        ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})

    Returns:
        json -- Информация о пользователе

`check_name(self, name, ses_id=None)`
:   Возвращает информацию о пользователе name
        [любой аутентифицированный пользователь может получить инфу о любом другом пользователе]

    Arguments:
        name {str} -- Имя пользователя

    Keyword Arguments:
        ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})

    Returns:
        json -- информация о пользователе

`get_provider_list(self, login, password, gp=None, ip=None)`
:   Возвращает информацию о провайдерах с группой gp

    Arguments:
        login {str} -- Пользователь, под которым можно получить группу провайдеров
        password {str} -- Пароль пользователя, под которым можно получить группу провайдеров

    Keyword Arguments:
        gp {str} -- Группа провайдеров (default: {None})
        ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})

    Returns:
        list -- Список провайдеров

`get_user_list(self, token, gp, ip=None, pid=None)`
:   Возвращает информацию о пользователях провайдера

    Arguments:
        token {str} -- Токен безопасности
        gp {str} -- Группа провайдеров

    Keyword Arguments:
        ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})
        pid {str} -- идентификатор провайдера (default: {None})

    Returns:
        list -- Список пользователей провайдера

`import_gp(self)`
:   Returns:
        list -- список групп провайдеров

`is_authenticated(self, ses_id=None)`
:   Возвращает информацию об аутентифицированном пользователе, если сессия аутентифицирована

    Keyword Arguments:
        ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})

    Returns:
        json -- информация о пользователе

`login(self, login, password, ses_id=None, gp=None, ip=None)`
:   Аутентифицирует сессию;
        Если пара "логин-пароль" аутентифицирует сессию приложения ses_id;
        Если пара "логин-пароль" неверна, выкидывает Forbidden

    Arguments:
        login {str} -- Логин пользователя
        password {str} -- Пароль пользователя

    Keyword Arguments:
        ses_id {str} -- Идентификатор сессии (default: {None})
        gp {str} -- Группа провайдеров (когда меллофон подключен к нескольким источникам данных) (default: {None})
        ip {str} -- ip компьютера пользователя для передачи в ф-цию проверки пользователя по логину и ip (default: {None})

`logout(self, ses_id=None)`
:   Разаутентифицирует указанную сессию приложения или текущую

    Keyword Arguments:
        ses_id {str} -- id сессии (по умолчанию текущая) (default: {None})

`set_settings(self, token, lockout_time=None, login_attempts_allowed=None)`
:   Изменение настроек меллофона

    Arguments:
        token {str} -- Токен безопасности

    Keyword Arguments:
        lockouttime {int} -- время в минутах, на которое будет блокироваться пользователь (default: {None})
        loginattemptsallowed {str} -- разрешенное количество неудачных попыток ввода пароля (default: {None})

    Returns:
        [type] -- [description]