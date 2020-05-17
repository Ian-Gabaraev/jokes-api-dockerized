from flask import current_app as app
from flask import jsonify
from flask import request
from flask import make_response

from flask_restful import Resource
from flask_restful import Api
from flask_restful import reqparse

from sqlalchemy.exc import IntegrityError

from .models import User
from .models import Joke
from .models import Action
from .models import db

from . import bcrypt

from datetime import datetime

from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity

import requests

jwt = JWTManager(app)


@app.route('/')
def index():
    """
    Index page endpoint
    :return: 204 No Content
    """
    return '', 204


def log_action(req_obj: request, user_id: int):
    """
    This subroutine allows logging registered users' activity
    :param req_obj: current request context
    :param user_id: actor's user_id
    :return: None
    """
    new_action = Action(
        user_ip_address=req_obj.remote_addr,
        action_time=datetime.now(),
        action_path=req_obj.path,
        user_id=user_id,
    )
    db.session.add(new_action)
    db.session.commit()


def compare(candidate: str, hashcode: str) -> bool:
    """
    This subroutine allows for validation of encrypted password
    :param candidate: candidate password
    :param hashcode: Bcrypt-hashed password
    :return: True if matched, else False
    """
    return bcrypt.check_password_hash(hashcode, candidate)


def within_bounds(user_id):
    """
    This subroutine check whether the User
    has not reached the limit of available Jokes
    :param user_id: User identity
    :return: boolean True or False
    """
    return len(
        Joke.query.filter_by(user_id=user_id).all()
    ) <= app.config['JOKES_LIMIT']


class Registration(Resource):
    """
    The registration endpoint takes
    two mandatory parameters:
    'username' and 'password',
    If successful, user's credentials are written
    to the database
    """
    parser = reqparse.RequestParser()
    parser.add_argument(
        'username',
        type=str,
        required=True
    )
    parser.add_argument(
        'password',
        type=str,
        required=True
    )

    def post(self):
        """
        Process POST requests to endpoint '/register' w/
        required parameters str: username and str: password
        :return: 400 Bad Request if username or password
        are not alphanumeric or shorter than 6 chars each,
        bigger than 20 chars each, else return 201 Created
        """
        for param in Registration.parser.parse_args().values():
            if not param.isalnum() or (len(param) < 6 or len(param) > 20):
                return make_response(jsonify(
                    error=app.config['BAD_PARAMETER']
                ), 400)

        new_user = User(
            username=Registration.parser.parse_args()['username'],
            password=bcrypt.generate_password_hash(
                Registration.parser.parse_args()['password'])
        )
        try:
            # Save the new user to the User table
            db.session.add(new_user)
            db.session.commit()
        # Trying to add a UNIQUE field twice violates database integrity
        except IntegrityError:
            return make_response('This user already exists', 400)
        else:
            return make_response('User created', 201)


@app.route('/login', methods=['POST'])
def login():
    """
    The login endpoints takes two mandatory:
    :parameter username
    :parameter password
    :return: 200 OK and JWT
    """

    # If password or username are not present in
    # the request, return 401 Unauthorized
    if not (request.form['username'] and request.form['password']):
        return make_response('Missing username/password', 401)

    # If requester user does not exist,
    # return 401 Unauthorized
    if not User.query.filter_by(username=request.form['username']).first():
        return make_response('No such user', 401)

    # If password and hash did not match, return
    # 401 Unauthorized
    if not compare(candidate=request.form['password'],
                   hashcode=User.query.filter_by(
                       username=request.form['username']).first().password):
        return make_response('Wrong password', 401)

    access_token = create_access_token(
        identity=User.query.filter_by(
            username=request.form['username']).first().id
    )

    # If credentials are correct, generate and return JWT
    return jsonify(access_token=access_token), 200


@app.route('/create-joke', methods=['PUT'])
@jwt_required
def create_joke():
    """
    Protected endpoint for creating new jokes
    :return: 201 Created
    """

    # Check whether User has not outgrown
    # his collection of Jokes

    try:
        assert within_bounds(get_jwt_identity())
    except AssertionError:
        return make_response('Your jokes collection is full', 403)

    # Check if joke content is present in the request
    try:
        assert 'content' in request.form
    except AssertionError:
        return make_response('No joke content present', 400)
    else:

        # Check if joke content length is within limits
        try:
            assert len(request.form['content']) <= 900
        except AssertionError:
            return make_response('Joke string is too long. '
                                 'Max allowed size is 900 characters', 400)
        else:

            this_joke = Joke.query.filter_by(
                content=request.form['content']).first()

            # Check if the User has this joke already
            if this_joke:
                return make_response('This joke already exists', 403)

            # Create and save new joke to Joke table
            new_joke = Joke(
                content=request.form['content'],
                user_id=get_jwt_identity()
            )
            db.session.add(new_joke)
            db.session.commit()
            return make_response('Joke created', 201)
    finally:
        log_action(request, get_jwt_identity())


@app.route('/import-joke', methods=['PUT'])
@jwt_required
def import_a_joke():
    """
    The endpoint for importing jokes
    :return: 201 if successful
    """

    # Check whether User has not outgrown
    # his collection of Jokes
    try:
        assert within_bounds(get_jwt_identity())
    except AssertionError:
        return make_response('Your jokes collection is full', 403)

    try:
        assert 'source' in request.form
    except AssertionError:
        return make_response('source is required', 400)
    else:

        # Check if server supports the source
        try:
            assert request.form['source'] in app.config['FOREIGN_API']
        except AssertionError:
            return make_response('This source is not supported', 404)
        else:
            content = requests.get(
                app.config['FOREIGN_API'][request.form['source']]
            ).json()['joke']

            # Check if the User has this joke already
            this_joke = Joke.query.filter_by(
                content=content
            ).first()

            # If it is present, refuse action and return 403 Forbidden
            if this_joke:
                return make_response('This joke already exists', 403)

            # Else, create and save the new joke
            new_joke = Joke(
                content=content,
                user_id=get_jwt_identity()
            )

            db.session.add(new_joke)
            db.session.commit()

            return make_response('Joke created', 201)

    finally:
        log_action(request, get_jwt_identity())


@app.route('/get-joke-by-id')
@jwt_required
def get_joke_by_id():
    """
    The endpoint for retrieving jokes by ID
    :return: 200 OK and Joke content
    """
    try:
        # Check if joke_id is present in the request
        assert 'joke_id' in request.form
    except AssertionError:
        return make_response('joke_id is a required parameter', 400)
    else:
        try:
            joke_obj = Joke.query.filter_by(
                joke_id=request.form['joke_id'],
                user_id=get_jwt_identity()
            ).first()
            # Check if Joke by joke_id exists
            assert joke_obj
        except AssertionError:
            return make_response('Nothing found', 404)
        else:
            return make_response(
                joke_obj.content, 200
            )
    finally:
        log_action(request, get_jwt_identity())


@app.route('/my-jokes')
@jwt_required
def get_my_jokes():
    """
    The endpoint for retrieving all the Jokes
    that belong to the User
    :return: 200 OK and jokes in JSON
    """
    try:
        # Check if User has jokes in the first place
        all_jokes = Joke.query.filter_by(user_id=get_jwt_identity()).all()
        assert all_jokes
    except AssertionError:
        # If none, return 204 No Content
        return make_response('', 204)
    else:
        # Else, generate a dictionary as joke_id:content
        result = {
            k: v.content for (k, v) in enumerate(all_jokes)
        }
        # Return dictionary as JSON
        return jsonify(result)
    finally:
        log_action(request, get_jwt_identity())


@app.route('/update-joke', methods=['PATCH'])
@jwt_required
def update_my_joke():
    """
    The endpoint for updating User's jokes
    :return: 204 No Content
    """
    try:
        # Check if joke_id and content are present in the request
        assert 'joke_id' in request.form
        assert 'content' in request.form
    except AssertionError:
        return make_response('joke_id and content are required', 400)
    else:

        # Check if the new joke content is withing the bounds
        try:
            assert len(request.form['content']) <= 900
        except AssertionError:
            return make_response(app.config['TOO_LONG'], 400)
        else:

            this_joke = Joke.query.filter_by(
                joke_id=request.form['joke_id'],
                user_id=get_jwt_identity()
            ).first()

            # If the joke does not exists, return 404 Not Found
            if not this_joke:
                return make_response('Nothing to patch', 404)

            this_joke.content = request.form['content']
            db.session.commit()
            return make_response('', 204)
    finally:
        log_action(request, get_jwt_identity())


@app.route('/delete-joke', methods=['DELETE'])
@jwt_required
def delete_my_joke():
    """
    The endpoint for deleting User's jokes
    :return: 200 OK and Joke content
    """
    try:
        # Check if joke_id is present in the request
        assert 'joke_id' in request.form
    except AssertionError:
        return make_response('joke_id is required', 400)
    else:

        this_joke = Joke.query.filter_by(
            joke_id=request.form['joke_id'],
            user_id=get_jwt_identity()
        ).first()

        try:
            # Check if Joke by this joke_id exists
            assert this_joke
        except AssertionError:
            return make_response('This joke does not exist', 404)
        else:
            # Delete the joke
            db.session.delete(this_joke)
            db.session.commit()
            # Return 200 OK and removed Joke content
            return make_response(this_joke.content, 200)

    finally:
        log_action(request, get_jwt_identity())


api = Api(app)
api.add_resource(Registration, '/register')
