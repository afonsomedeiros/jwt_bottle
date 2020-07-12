import bottle
from .jwt_bottle import JWTPlugin, auth_required
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