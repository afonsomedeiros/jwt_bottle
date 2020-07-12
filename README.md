# Plugin que implementa autenticação com JWT para o aplicações Bottle.

### Instalação.

É necessário instalar `bottle` (por se tratar de um plugin para aplicações com bottle) em seguida pode realizar a instalação do plugin.

```sh
$ pip install bottle
```

Caso aconteça algum erro com relação a importação de módulo do python-jose ou pycrypto, pode instalar os pacotes abaixo também.

```sh
$ pip install python-jose
$ pip install pycrypto
```

Exemplo de uso:

```py
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
```

Teste efetuado utilizando httpie, para instalar basta executar `pip install httpie`

```sh
# /auth é o endpoint padrão para autenticar.
$ http POST http://127.0.0.1:8080/auth email=afonso@afonso.com password=123456

HTTP/1.0 200 OK
Content-Length: 128
Content-Type: application/json
Date: Sun, 12 Jul 2020 03:59:19 GMT
Server: WSGIServer/0.2 CPython/3.8.2

{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZXhwIjoxNTk0NTI5OTU5fQ.1hmo_Fkg7-OKs0VDDil6dUnDv5FvmIkIYAjl6nzewwY"
}

$ http http://127.0.0.1:8080/user Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZXhwIjoxNTk0NTI5OTU5fQ.1hmo_Fkg7-OKs0VDDil6dUnDv5FvmIkIYAjl6nzewwY

HTTP/1.0 200 OK
Content-Length: 15
Content-Type: text/html; charset=UTF-8
Date: Sun, 12 Jul 2020 04:01:09 GMT
Server: WSGIServer/0.2 CPython/3.8.2

Usuario: Afonso
```

-> Desatualizado ~A classe usuario precisa possuir um campo para "email", "password", precisa implementar os métodos "gen_hash" e "verify". A autenticação só é valida utilizando um endereço de email válido, caso queira utilizar outro campo para autenticação que não siga o padrão de um email, deverá realizar a alteração no modo "hard code" isto é, alterando o plugin na mão.~

É necessário implementar uma classe para a autenticação do usuário, essa classe vai carregar as regras de autenticação de cada aplicação, no caso do exemplo Criei uma classe `Auth` que seguindo a regra implementa dois métodos estáticos `authenticate` e `get_user`. O método `authenticate` pode receber qualquer parametro para autenticação o que flexibiliza como realizar o POST com os dados do usuário, já o método `get_user` obrigatóriamente utiliza o id do usuário, portanto deverá implementar uma forma de consulta utilizando o id.

O método authenticate deve retornar um objeto que possua um atributo com nome `id` para gerar o payload para o Token.

Com a mudança feita não é mais obrigatório o uso de uma classe peewee Model, agora pode utilizar o ORM que quiser e implementar sua própria forma de authenticar um usuário.

Código baseado na lib: https://github.com/agile4you/bottle-jwt