from jose import jwt
import datetime


class Token(object):
    """Classe que gerencia criação de tokens.

    Args:
        payload ([dict]): Dicionarios com dados para gerar token.
        secret ([str]): Secredo de criptografia do Token.
        header ([dict]): Caso seja necessário cabecalhos adicionais ao token.
        expire_time ([int]): Tempo em horas que leva para o token expirar.
    """

    def __init__(self, payload={}, secret='', expire_time=1, header=None):
        self.header = header
        self.payload = payload
        self.secret = secret
        self.expire_time = expire_time

    def create(self):
        """Gera token

        Returns:
            [str]: Token gerado com base nos dados de instancia da classe.
        """
        if 'exp' in self.payload:
            self.payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(hours=self.expire_time)
        return jwt.encode(self.payload, self.secret, headers=self.header)

    def decode(self, token):
        """decodifica token e retorna payload original, caso token
        ainda esteja valido.

        Args:
            token ([str]): token para ser decodificado.

        Returns:
            [dict]: payload utilizado para criação do token.
        """
        try:
            return jwt.decode(token, self.secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError as err:
            return err

    def refresh(self, token):
        """Atualiza token para um token valido.
        obs: Ainda é necessário determinar uma forma de retorno e utilização
        desta funcionálidade.

        Args:
            token (str): token para ser atualizado.

        Returns:
            str: novo token criado.
        """
        self.payload = self.decode(token)
        if 'exp' in self.payload:
            self.payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        return self.create()

    def verify(self, token, refresh=False):
        """verifica se token é valido.

        Args:
            token (str): token a ser validado
            refresh (bool, optional): Caso token deva ser atualizado setar como
            True. Valor é False.

        Returns:
            str: Retorna token ou um novo token.
        """
        try:
            if self.decode(token):
                if refresh:
                    return self.refresh(token)
                return token
            return False
        except Exception as e:
            return r