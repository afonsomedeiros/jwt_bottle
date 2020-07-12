# Plugin que implementa autenticação com JWT para o aplicações Bottle.

Exemplo de uso:

```py
import bottle
from JwtPlugin import JWTPlugin, auth_required
from peewee import SqliteDatabase, Model, CharField, DateField, DoesNotExist
from passlib.hash import pbkdf2_sha512 as hsh # aqui utilizei o pass lib, mas a escolha é livre.
from hashlib import md5


db = SqliteDatabase(":memory:")


class Users(Model):
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

app = bottle.Bottle()

jwt = JWTPlugin("asfasdf", Users)

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

A classe usuario precisa possuir um campo para "email", "password", precisa implementar os métodos "gen_hash" e "verify". A autenticação só é valida utilizando um endereço de email válido, caso queira utilizar outro campo para autenticação que não siga o padrão de um email, deverá realizar a alteração no modo "hard code" isto é, alterando o plugin na mão.

Código baseado na lib: https://github.com/agile4you/bottle-jwt