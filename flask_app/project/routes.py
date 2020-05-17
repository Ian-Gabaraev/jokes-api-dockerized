from flask import current_app as app
from flask import jsonify
from flask import request
from flask import make_response
from flask import Response

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
import json

jwt = JWTManager(app)


@app.route('/')
def index():
    """
    Index page endpoint
    :return: 204 No Content
    """
    return Response(response='', status=204, content_type='text/plain')


def log_action(request_object: request, user_id: int):
    """
    This subroutine allows logging registered users' activity
    :param request_object: current request context
    :param user_id: actor's user_id
    :return: None
    """
    new_action = Action(
        user_ip_address=request_object.remote_addr,
        action_time=datetime.now(),
        action_path=request_object.path,
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


def within_bounds(user_id: int) -> bool:
    """
    This subroutine check whether the User
    has not reached the limit of available Jokes
    :param user_id: User identity
    :return: boolean True or False
    """
    all_users_jokes = Joke.query.filter_by(user_id=user_id).all()
    return len(all_users_jokes) <= app.config['JOKES_LIMIT']


@app.route('/register', methods=['POST'])
def register():
    """
    Process POST requests to endpoint '/register' w/
    required parameters str: username and str: password
    :return: 400 Bad Request if username or password
    are not alphanumeric or shorter than 6 chars each,
    bigger than 20 chars each, else return 201 Created
    """
    try:
        assert 'username' in request.form
        assert 'password' in request.form
    except AssertionError:
        return Response(response=app.config['BAD_PARAMETER'],
                        status=400, content_type='text/plain')
    else:

        try:

            for parameter in request.form.values():
                assert parameter.isalnum()
                assert len(parameter) >= 6
                assert len(parameter) <= 20

        except AssertionError:
            return Response(response=app.config['BAD_PARAMETER'],
                            status=400, content_type='text/plain')
        else:

            this_user = User.query.filter_by(
                username=request.form['username']
            ).first()

            if not this_user:
                new_user = User(
                    username=request.form['username'],
                    password=bcrypt.generate_password_hash(
                        request.form['password'])
                )

                db.session.add(new_user)
                db.session.commit()

                return Response(response="You are registered",
                                status=201, content_type='text/plain')

        return Response(response="This user already exists",
                        status=403, content_type='text/plain')


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
        return Response(response="Missing username/password",
                        status=401, content_type='text/plain')

    # If requester user does not exist,
    # return 401 Unauthorized

    if not User.query.filter_by(username=request.form['username']).first():
        return Response(response="No such user",
                        status=401, content_type='text/plain')

    # If password and hash did not match, return
    # 401 Unauthorized
    if not compare(candidate=request.form['password'],
                   hashcode=User.query.filter_by(
                       username=request.form['username']).first().password):

        return Response(response="Wrong password",
                        status=401, content_type='text/plain')

    access_token = create_access_token(
        identity=User.query.filter_by(
            username=request.form['username']).first().id
    )

    # If credentials are correct, generate and return JWT

    return Response(response=json.dumps({'access_token': access_token}),
                    status=200, content_type='application/json')


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

        return Response(response="Your jokes collection is full",
                        status=403, content_type='text/plain')

    # Check if joke content is present in the request
    try:
        assert 'content' in request.form
    except AssertionError:
        return Response(response="No joke content present",
                        status=400, content_type='text/plain')
    else:

        # Check if joke content length is within limits
        try:
            assert len(request.form['content']) <= 900
        except AssertionError:
            return Response(response=app.config['TOO_LONG'],
                            status=400, content_type='text/plain')

        else:

            this_joke = Joke.query.filter_by(
                content=request.form['content']).first()

            # Check if the User has this joke already
            if this_joke:
                return Response(response="This joke already exists",
                                status=403, content_type='text/plain')

            # Create and save new joke to Joke table
            new_joke = Joke(
                content=request.form['content'],
                user_id=get_jwt_identity()
            )
            db.session.add(new_joke)
            db.session.commit()

            return Response(response="Joke created",
                            status=201, content_type='text/plain')

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

        return Response(response="Your jokes collection is full",
                        status=403, content_type='text/plain')

    try:
        assert 'source' in request.form
    except AssertionError:
        return Response(response="Your jokes collection is full",
                        status=400, content_type='text/plain')
    else:

        # Check if server supports the source
        try:
            assert request.form['source'] in app.config['FOREIGN_API']
        except AssertionError:

            return Response(response="This source is not supported",
                            status=403, content_type='text/plain')
        else:
            # Request the joke content from foreign API
            content = requests.get(
                app.config['FOREIGN_API'][request.form['source']]
            ).json()['joke']

            # Check if the User has this joke already
            this_joke = Joke.query.filter_by(
                content=content
            ).first()

            # If it is present, refuse action and return 403 Forbidden
            if this_joke:
                return Response(response="This joke already exists",
                                status=403, content_type='text/plain')

            # Else, create and save the new joke
            new_joke = Joke(
                content=content,
                user_id=get_jwt_identity()
            )

            db.session.add(new_joke)
            db.session.commit()

            return Response(response="Joke created",
                            status=201, content_type='text/plain')

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
        return Response(response="joke_id is a required parameter",
                        status=400, content_type='text/plain')
    else:
        try:
            joke_obj = Joke.query.filter_by(
                joke_id=request.form['joke_id'],
                user_id=get_jwt_identity()
            ).first()
            # Check if Joke by joke_id exists
            assert joke_obj
        except AssertionError:
            return Response(response="Nothing found",
                            status=404, content_type='text/plain')
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
        return Response(response="",
                        status=204, content_type='text/plain')
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
        return Response(response="joke_id and content are required",
                        status=400, content_type='text/plain')
    else:

        # Check if the new joke content is withing the bounds
        try:
            assert len(request.form['content']) <= 900
        except AssertionError:
            return Response(response=app.config['TOO_LONG'],
                            status=400, content_type='text/plain')
        else:

            this_joke = Joke.query.filter_by(
                joke_id=request.form['joke_id'],
                user_id=get_jwt_identity()
            ).first()

            # If the joke does not exists, return 404 Not Found
            if not this_joke:
                return Response(response="Nothing to patch",
                                status=404, content_type='text/plain')

            this_joke.content = request.form['content']
            db.session.commit()
            return Response(response="",
                            status=204, content_type='text/plain')
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
        return Response(response="joke_id is required",
                        status=400, content_type='text/plain')
    else:

        this_joke = Joke.query.filter_by(
            joke_id=request.form['joke_id'],
            user_id=get_jwt_identity()
        ).first()

        try:
            # Check if Joke by this joke_id exists
            assert this_joke
        except AssertionError:
            return Response(response="This joke does not exist",
                            status=404, content_type='text/plain')
        else:
            # Delete the joke
            db.session.delete(this_joke)
            db.session.commit()
            # Return 200 OK and removed Joke content
            return Response(response=this_joke.content,
                            status=200, content_type='text/plain')

    finally:
        log_action(request, get_jwt_identity())
