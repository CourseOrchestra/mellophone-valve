# coding: utf-8

def default_sesid(method):
    def wrapper(self, *args, **kwargs):
        if not kwargs.get('ses_id'):
            kwargs['ses_id'] = self.session_id

        return method(self, *args, **kwargs)

    return wrapper
