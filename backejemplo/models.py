from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    email=db.Column(db.String(50), nullable=False, unique=True) 
    username= db.Column(db.String(50), nullable=True, unique=True)
    password=db.Column(db.String(10), nullable=False)
    name= db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return "<User %r>" % self.username
    
    def serialize(self):
        return{
            "email":self.email,
            "username":self.username,
            "name":self.name,
            "id":self.id
        }