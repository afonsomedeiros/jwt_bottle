import bottle
import re
from operator import attrgetter
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
        auth_model (Python class): Classe que provê métodos de autenticação.
        A classe precisa implementar dois métodos estáticos:
            - authenticate.
            - get_user
        auth_endpoint (str): Rota de autenticação. Padrão é "/auth"
        refresh (bool): Determina se é ou não para que token seja atualizavel.

    Raises:
        PluginError: [description]

    Returns:
        [type]: [description]
    """

    name = "JWTPlugin"
    api = 2

    def __init__(self, secret, auth_model, auth_endpoint="/auth", refresh=False):
        self.secret = secret
        self.auth_model = auth_model
        self.refresh = refresh
        self.auth_endpoint = auth_endpoint

    def setup(self, app):
        for other in app.plugins:
            if not isinstance(other, JWTPlugin):
                @app.post(self.auth_endpoint)
                def auth_handler():
                    if hasattr(self.auth_model, 'authenticate') and hasattr(self.auth_model, 'get_user'):
                        data = bottle.request.json
                        user = self.auth_model.authenticate(**data)
                        if user:
                            payload = {'id': user.id, 'exp': ''}
                            token = Token(payload=payload, secret=self.secret)
                            return {"token": token.create()}
                        else:
                            return {'error': "Usuário inválido."}
                    else:
                        return {'error': "Classe utilizada para auntenticação não atende o padrão"}

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
                kwargs['token'] = token
            else:
                decoded = Token(secret=self.secret).decode(t)

            if hasattr(self.auth_model, 'authenticate') and hasattr(self.auth_model, 'get_user'):
                kwargs['user'] = self.auth_model.get_user(decoded['id'])
                return injector(*args, **kwargs)
            else:
                return {'error': "Classe utilizada para auntenticação não atende o padrão"}

        return wrapper