from typing import Callable, List, Mapping
from functools import partial

from bottle import Bottle, PluginError, request, response
from jose.jwt import decode

from .jwt_auth import Token


def auth_required(callable: Callable):
    setattr(callable, "auth_required", True)
    return callable


class BaseAuth(object):
    @staticmethod
    def authenticate(*args, **kwargs):
        pass

    @staticmethod
    def get_user(*args, **kwargs):
        pass


class JWTPluginError(Exception):
    ...


class JWTPlugin(object):
    name = "JWTPlugin"
    api = 2

    def __init__(self, secret: str, configs: List[Mapping[str, object]], payload: List[str] = None, debug: bool = False) -> None:
        """
            config: List[Mapping[str, object]]: Objeto que conterá classes e endpoints para autenticação.
            ex:
            config[0] -> {'model': AdminAuth, 'endpoint': '/admin/auth'}
            config[1] -> {'model': UserAuth, 'endpoint': '/auth'}

            A classe responsável pela autenticação (AdminAuth, UserAuth) devem implementar uma interface.

            payload exemplo: {"id": None, "email": None}
        """
        self.secret = secret
        self.configs = configs
        self.payload = payload

    def setup(self, app: Bottle):
        for plugin in app.plugins:
            if isinstance(plugin, JWTPlugin):
                raise PluginError("Encontrado uma outra instancia do plugin.")
            else:
                for config in self.configs:
                    model = config['model']
                    if issubclass(model, BaseAuth):
                        auth_handler_function = """def _AUTHNAMEFUNC_(model, configs, secret, pl={}):
    data = request.json
    user = model.authenticate(**data)
    if not user and len(configs) > 1:
        return ""
    payload = {}
    if pl:
        for key in pl:
            payload[key] = getattr(user, key) if hasattr(user, key) else None
            if payload[key] == None:
                del payload[key]
    else:
        payload["id"] = user.id if hasattr(user, "id") else None
        if payload["id"] == None:
            del payload["id"]
        if not payload:
            raise JWTPluginError("Modelo não possui nenhum parametro compativel com atributos de autenticação.")
        if not "exp" in payload:
            payload['exp'] = ""
    token = Token(payload=payload, secret=secret, expire_time=0.05)
    payload['token'] = token.create()
    refresh_token = Token(payload, secret=secret)
    response.content_type = "application/json"
    response.status = 200
    return {"token": token.create(), "refresh_token": refresh_token.create()}
"""
                        refresh_token_handle_function = """def _REFRESHNAMEFUNC_(model, configs, secret, pl={}):
    rt = request.get_header("Refresh-Jwt")
    decoded = Token(secret=secret).decode(rt)
    print(f"decoded -> {decoded}")
    print(f"pl -> {pl}")
    token = decoded['token']
    del decoded['token']
    user = model.get_user(**decoded)
    if decoded:
        payload = {}
        if pl:
            for key in pl:
                payload[key] = getattr(user, key) if hasattr(user, key) else None
                if payload[key] == None:
                    del payload[key]
        else:
            payload["id"] = user.id if hasattr(user, "id") else None
            if payload["id"] == None:
                del payload["id"]
                if not payload:
                    raise JWTPluginError("Modelo não possui nenhum parametro compativel com atributos de autenticação.")
            if not "exp" in rt:
                payload['exp'] = ""
        print(f"payload -> {payload}")
        token = Token(payload=payload, secret=secret, expire_time=0.05)
        payload['token'] = token.create()
        refresh_token = Token(payload, secret=secret)
        response.content_type = "application/json"
        response.status = 200
        return {"token": token.create(), "refresh_token": refresh_token.create()}
"""
                        auth_handler_function = auth_handler_function.replace(
                            "_AUTHNAMEFUNC_", config['auth_name'])
                        exec(auth_handler_function)
                        refresh_token_handle_function = refresh_token_handle_function.replace(
                            "_REFRESHNAMEFUNC_", config['refresh_name'])
                        exec(refresh_token_handle_function)
                        # model, configs, pl, secret
                        app.post(config['endpoint'], callback=partial(
                            eval(config['auth_name']), model, self.configs, self.secret, self.payload))
                        app.post(f"{config['endpoint']}/refresh",
                                 callback=partial(eval(config['refresh_name']), model, self.configs, self.secret, self.payload))
                    else:
                        raise JWTPluginError(
                            "Não implementa interface de autenticação.")

    def apply(self, callback, context):
        def injector(*args, **kwargs):
            return callback(*args, **kwargs)

        if not hasattr(callback, "auth_required"):
            return injector

        def wrapper(*args, **kwargs):
            header_token = request.get_header("Authorization")

            decoded = Token(secret=self.secret).decode(header_token)
            for config in self.configs:
                model = config['model']
                user = model.get_user(**decoded)
                if user:
                    kwargs["user"] = user
                    return injector(*args, **kwargs)
            return injector(*args, **kwargs)

        return wrapper
