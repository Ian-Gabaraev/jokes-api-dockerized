"""Flask configuration"""


class Config:
    """Setting up config variables"""

    # General
    FLASK_ENV = "development"
    TESTING = True

    # Database
    SQLALCHEMY_DATABASE_URI = "sqlite:///sqlite_db/catalogue.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT
    JWT_SECRET_KEY = 'super-secret'

    # Tests
    FAKE_DATABASE_URI = "sqlite:///tests/test.db"
    FAKE_USER = 'baJeKcrEed09'
    FAKE_USER_PASSWORD = 'XenomorpH1993'

    JOKE_FAKE_USER = 'xamarine099'
    JOKE_FAKE_USER_PASSWORD = 'xiliojio31'

    FAKE_JOKE = 'A horse and a pigeon walk into a bar...'
    ANOTHER_FAKE_JOKE = 'What\'s the best thing about Switzerland? ' \
                        'I don\'t know, but the flag is a big plus.'

    # Messages
    BAD_PARAMETER = "password and username are required" \
                    "username and password can only contain digits " \
                    "and letters and must be at least 6 " \
                    "characters long, 20 characters at max"
    TOO_LONG = b"Joke string is too long. Max allowed size is 900 characters"

    # Bounds
    JOKES_LIMIT = 100

    # Foreign APIs
    FOREIGN_API = {
        'geek-jokes': 'https://geek-jokes.sameerkumar.website/api?format=json',
    }
