import bottle
from jwt_bottle import JWTPlugin, auth_required
from peewee import (SqliteDatabase, Model, CharField,
                    DateField, DoesNotExist) # aqui utilizei o peewee, mas a escolha é livre.
from passlib.hash import pbkdf2_sha512 as hsh # aqui utilizei o passlib, mas a escolha é livre.
from hashlib import md5


db = SqliteDatabase(":memory:")


class Users(Model):
    """Classe usuário.
    """
    name = CharField(max_length=50)
    last_name = CharField(max_length=50)
    email = CharField(max_length=200)
    password = CharField(max_length=300)
    birthday = DateField()

    def gen_hash(self):
        _secret = md5("123456".encode()).hexdigest()
        _password = md5(self.password.encode()).hexdigest()
        self.password = hsh.hash(_secret+_password)

    def verify(self, password):
        _secret = md5("123456".encode()).hexdigest()
        _password = md5(password.encode()).hexdigest()
        return hsh.verify(_secret+_password, self.password)

    class Meta:
        database = db


class Auth(object):
    """Classe para autenticação.
    Precisa conter um método estático chamado authenticate e outro
    chamado get_user.

    Os parametros de authenticate ficam a critério do método post.

    O padrão é receber uma requisição POST enviando dados no formato JSON.
    Esses dados são empacotados no argumento kwargs do método authenticate.

    para identificar o usuário é necessário realizar a consulta utilizando
    um ID.
    """

    @staticmethod
    def authenticate(*args, **kwargs):
        """Método para autenticação, aqui utilizei uma classe chamada
        Users implementada com o ORM peewee e uma simples regra de 
        autenticação apresentada pelo Eduardo Mendes.
        link: https://www.youtube.com/watch?v=ieGA91ExOH0

        Returns:
            Users: dicionário contendo id para gerar o token.
            OBS: é necessário possuir um atributo "id" para gerar o token.
        """
        try:
            if "email" in kwargs and "password" in kwargs:
                user = Users.get(Users.email==kwargs['email'])
                if user.verify(kwargs['password']):
                    return user
            return None
        except DoesNotExist as err:
            return {"erro": f"Usuário {kwargs['email']} não localizado"}

    @staticmethod
    def get_user(user_id: int):
        """Classe para resgatar usuario autenticado
        utilizando a decodificação de um token.

        Args:
            user_id ([int]): identificador do usuário.

        Returns:
            Users: retorna usuário autenticado pelo Token.
        """
        try:
            user = Users.get_by_id(user_id)
            if user:
                return user
            return None
        except DoesNotExist as err:
            return {"erro": f"Usuário {kwargs['email']} não localizado"}



app = bottle.Bottle()

jwt = JWTPlugin("asfasdf", Auth)

app.install(jwt)


@auth_required
@app.get("/user")
def index(user):
    return f"Usuario: {user.name}"


if __name__ == "__main__":
    Users.create_table()
    user = Users(name="Afonso", last_name="Medeiros", email="afonso@afonso.com", password="123456", birthday="2020-01-01")
    user.gen_hash()
    user.save()
    
    app.run(debug=True, reloader=True)