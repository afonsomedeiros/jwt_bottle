import bottle
import re
from operator import attrgetter
from peewee import DoesNotExist, Model
from bottle import PluginError

from .jwt_auth import Token


email_re = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'


def auth_required(callable):
    setattr(callable, 'auth_required', True)
    return callable


class JWTPlugin(object):
    """Plugin que prove autenticacao e token JWT.

    Args:
        secret (str): Segredo para criptografar Token
        auth_model (Peewee Model): Classe baseada no peewee model
        que referencia a classe que deve ser utilizada para autenticação.
        obs: A Classe peewee para autenticação deve obedecer um determinado padrão
        para que funcione corretamente.
        auth_endpoint (str): Rota de autenticação. Padrão é "/auth"
        refresh (bool): Determina se é ou não para que token seja atualizavel.

    Raises:
        PluginError: [description]

    Returns:
        [type]: [description]
    """

    name = "JWTPlugin"
    api = 2

    def __init__(self, secret, auth_model: Model, auth_endpoint="/auth", refresh=False):
        self.secret = secret
        self.auth_model = auth_model
        self.refresh = refresh
        self.auth_endpoint = auth_endpoint

    def setup(self, app):
        for other in app.plugins:
            if not isinstance(other, JWTPlugin):
                @app.post(self.auth_endpoint)
                def auth_handler():
                    data = bottle.request.json
                    l = []
                    password = ''
                    for k in data.keys():
                        if re.match(email_re, data[k]):
                            l.append(attrgetter(k)(self.auth_model)==data[k])
                        else:
                            password = data[k]
                    user = self.auth_model.get(*l)
                    if user.verify(password):
                        payload = {
                            'id': user.id,
                            'exp': ''
                        }
                        token = Token(payload=payload, secret=self.secret)
                        return {"token": token.create()}
                    else:
                        return {'error': "Usuário inválido."}

            else:
                raise PluginError("Encontrado uma outra instancia do plugin.")

    def apply(self, callback, context):
        def injector(*args, **kwargs):
            return callback(*args, **kwargs)

        if not hasattr(callback, 'auth_required'):
            return injector

        def wrapper(*args, **kwargs):
            t = bottle.request.get_header('Authorization')
            if self.refresh:
                token = Token(secret=self.secret).refresh(t)
                decoded = Token(secret=self.secret).decode(token)
            else:
                decoded = Token(secret=self.secret).decode(t)
            kwargs['user'] = self.auth_model.get(attrgetter('id')(self.auth_model)==decoded['id'])
            return injector(*args, **kwargs)

        return wrapper