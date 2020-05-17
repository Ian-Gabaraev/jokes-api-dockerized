from . import db


class User(db.Model):
    """Table of registered Users"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    jokes = db.relationship('Joke', backref='user',
                            lazy=True, cascade='all, delete')
    actions = db.relationship('Action', backref='user',
                              lazy=True, cascade='all, delete')

    def __repr__(self):
        return '<User %r>' % self.username


class Joke(db.Model):
    """Table of Users' Jokes w/ many-to-one relationship w/ User"""
    joke_id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=False)

    def __repr__(self):
        return '<Joke %r>; of user %r' % (self.content, self.user_id)


class Action(db.Model):
    """Table of logged Actions performed by registered Users
    w/ many-to-one relationship w/ User"""
    action_id = db.Column(db.Integer, primary_key=True)
    user_ip_address = db.Column(db.String, nullable=False)
    action_time = db.Column(db.DateTime, nullable=False)
    action_path = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=False)

    def __repr__(self):
        return '<Action by user_id %r> registered at %r' % \
               (self.user_id, self.action_time)
