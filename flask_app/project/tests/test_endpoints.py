from project.models import db
from project.models import Joke
from project.models import User
from project import create_app

import sys
import os
import unittest
import json
import random
from sqlalchemy.orm.exc import UnmappedInstanceError

# Fixes the relative import issue for Travis CI
sys.path.append(os.getcwd() + '/..')


app = create_app()

tester = app.test_client()


class TestIfTablesExist(unittest.TestCase):
    """
    Test if tables are present and initialized:
    Get all the existing table names from the database engine,
    compare them against all the db.Model subclasses
    """

    def test_if_all_tables_are_present(self):
        with app.app_context():
            self.assertEqual(
                len(
                    set(db.engine.table_names()).difference(
                        set([table.__tablename__ for table
                             in db.Model.__subclasses__()])
                    )),
                0)


class IndexPageTestCase(unittest.TestCase):

    def test_empty_204_response_to_index_page(self):
        """
        Test if request to index page returns 204 No Content
        """
        response = tester.get('/', content_type='html/text')

        self.assertEqual(response.status_code, 204)


class RegistrationResourceTestCase(unittest.TestCase):
    """
    Test sign up functionality
    Test-case 1: register with good credentials
    Test-case 2: register under existing name
    Test-case 3: register with undersized credentials
    Test-case 4: register without password
    """

    @staticmethod
    def register_fake_user(username, password, feedback=False):
        """
        Create new user
        :param username: user's name
        :param password: user's password
        :param feedback: enable/disable feedback
        :return: if feedback == True -> Response
        """
        response = tester.post('/register', data=dict(
            username=username,
            password=password
        ))
        if feedback:
            return response

    @staticmethod
    def get_user_id(username):
        """
        Return user_id of said user
        :param username: user's name in User table
        :return: User.id object
        """
        with app.test_request_context():
            identity = User.query.filter_by(
                username=username).first().id
            return identity

    @staticmethod
    def get_user_object(username):
        """
        Get User object for said user
        :param username: user's name
        :return: User object
        """
        with app.app_context():
            user = User.query.filter_by(username=username).first()
        return user

    @staticmethod
    def delete_user(username):
        """
        Remove said user from User table
        :param username: user's name
        :return: None
        """
        with app.test_request_context():
            user = RegistrationResourceTestCase.get_user_object(username)
            try:
                db.session.delete(user)
                db.session.commit()
            except UnmappedInstanceError:
                pass

    def test_register_new_user(self):
        """
        Test if newly created user is in User table
        and status code is 201 Created
        """
        response = RegistrationResourceTestCase.register_fake_user(
            app.config['FAKE_USER'],
            app.config['FAKE_USER_PASSWORD'],
            feedback=True
        )
        self.fake_user = RegistrationResourceTestCase.get_user_object(
            username=app.config['FAKE_USER'])
        self.assertTrue(self.fake_user)
        self.assertEqual(response.status_code, 201)

    def test_attempt_to_register_under_existing_username(self):
        """
        Then, test if attempt to register under existing username
        returns 400 Bad Request
        """
        RegistrationResourceTestCase.register_fake_user(
            app.config['FAKE_USER'],
            app.config['FAKE_USER_PASSWORD'],
            feedback=False
        )
        response = RegistrationResourceTestCase.register_fake_user(
            app.config['FAKE_USER'],
            app.config['FAKE_USER_PASSWORD'],
            feedback=True
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, b'This user already exists')

    def test_registration_with_wrongly_sized_credentials(self):
        """
        Test if request to registration resource with
        wrongly sized credentials returns 400 Bad Request
        """
        response = tester.post('/register', data=dict(
            username='ian', password=100
        ))

        self.assertEqual(response.status_code, 400)

    def test_registration_with_missing_credential(self):
        """
        Test if request to registration resource without
        password returns 400 Bad Request
        """
        response = tester.post('/register', data=dict(
            username='ian'
        ))

        self.assertEqual(response.status_code, 400)

    def tearDown(self):
        """
        Remove the fake row from the User table
        """
        RegistrationResourceTestCase.delete_user(
            username=app.config['FAKE_USER']
        )


class LoginTestCase(unittest.TestCase):
    """
    Test log in functionality
    Test-case 1: log in with good credentials
    Test-case 2: log in with bad password
    Test-case 3: log in unregistered user
    Test-case 4: log in without password
    """

    @staticmethod
    def login_fake_user(username, password, jwt=False):
        """
        Log in said user
        :param username: user's name
        :param password: user's password
        :param jwt: enable to return JWT
        :return: if jwt == False -> Response, else JWT
        """
        response = tester.post('/login', data=dict(
            username=username,
            password=password
        ))
        if not jwt:
            return response
        return json.loads(response.data.decode('utf-8'))['access_token']

    @staticmethod
    def quick_setup_fake_user(username, password):
        """
        Saves time by creating a user and generating JWT synchronously
        :param username: user's name
        :param password: user's password
        :return: JWT: str
        """
        RegistrationResourceTestCase.register_fake_user(
            username, password
        )
        return LoginTestCase.login_fake_user(
            username, password, jwt=True
        )

    def setUp(self):
        """
        First, register a new user in the User table
        """
        RegistrationResourceTestCase.register_fake_user(
            username=app.config['FAKE_USER'],
            password=app.config['FAKE_USER_PASSWORD']
        )

    def test_attempt_to_login_a_registered_user_with_correct_credentials(self):
        """
        Test if logging in with correct credentials returns 200 OK
        and contains a JWT
        """
        response = LoginTestCase.login_fake_user(
            username=app.config['FAKE_USER'],
            password=app.config['FAKE_USER_PASSWORD']
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', json.loads(
            response.data.decode('utf-8')))

    def test_attempt_to_login_a_registered_user_with_wrong_password(self):
        """
        Test if logging in with wrong password returns 401 Unauthorized
        """
        response = LoginTestCase.login_fake_user(
            username=app.config['FAKE_USER'],
            password='deliberately'
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, b'Wrong password')

    def test_attempt_to_login_an_unregistered_user(self):
        """
        Test if logging in with wrong username returns 401 Unauthorized
        """
        response = LoginTestCase.login_fake_user(
            username='dummyusername',
            password='dummpassword'
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, b'No such user')

    def test_attempt_to_login_without_a_credential(self):
        """
        Test if logging in with wrong password returns 400 Bad Request
        """
        response = tester.post('/login', data=dict(
            username=app.config['FAKE_USER'],
        ))
        self.assertEqual(response.status_code, 400)

    def tearDown(self):
        """
        Remove the fake row from the User table
        """
        RegistrationResourceTestCase.delete_user(
            username=app.config['FAKE_USER']
        )


class BasicJokesResourceTestCase(unittest.TestCase):
    """
    Test creating jokes with JWT
    Test-case 1: create joke with proper parameters
    Test-case 2: attempt to create over-sized joke
    Test-case 3: attempt to create joke without content
    """

    access_token = None

    humongous_string = ''.join(
        [chr(random.randint(65, 122)) for _ in range(901)]
    )

    @staticmethod
    def get_joke_object(user_id, content=None, by_joke_id=None):
        """
        Retrieve joke_id of said joke
        :param user_id: joke owner's user_id
        :param content: joke text
        :param by_joke_id: unique Joke id
        :return: Joke instance
        """
        if not by_joke_id:
            with app.app_context():
                this_joke = Joke.query.filter_by(
                    user_id=user_id,
                    content=content).first()
                return this_joke
        else:
            with app.app_context():
                return Joke.query.filter_by(
                    user_id=user_id,
                    joke_id=by_joke_id).first()

    @staticmethod
    def create_joke(content, access_token, feedback=False):
        """
        Create new joke in Joke table
        :param content: joke text
        :param access_token: JSON Web Token
        :param feedback: enable/disable feedback
        :return: if feedback == True -> Response
        """
        response = tester.put(
            '/create-joke',
            data=dict(
                content=content),
            headers=dict(Authorization='Bearer ' + access_token)
        )
        if feedback:
            return response

    @staticmethod
    def delete_joke(user_id, content):
        """
        Delete said joke from Joke table
        :param user_id: joke owner's user_id
        :param content: joke text
        :return: None
        """
        with app.test_request_context():
            fake_joke = Joke.query.filter_by(
                user_id=user_id,
                content=content
            ).first()
            db.session.delete(fake_joke)
            db.session.commit()

    def setUp(self):
        """
        Spawning one User and logging it in
        """
        # First, register a new user in the User table"""
        RegistrationResourceTestCase.register_fake_user(
            app.config['JOKE_FAKE_USER'],
            app.config['JOKE_FAKE_USER_PASSWORD']
        )

        # Then, log in and retrieve JWT
        self.access_token = LoginTestCase.login_fake_user(
            app.config['JOKE_FAKE_USER'],
            app.config['JOKE_FAKE_USER_PASSWORD'],
            jwt=True
        )

        # Get id of User than made the request
        self.identity = RegistrationResourceTestCase.get_user_id(
            app.config['JOKE_FAKE_USER']
        )

    def test_creating_a_joke_with_correct_parameters(self):
        """
        Test if submitting correct parameters to
        create-joke endpoint returns 201 Created
        """
        # Create new joke
        response = BasicJokesResourceTestCase.create_joke(
            content=app.config['FAKE_JOKE'],
            access_token=self.access_token,
            feedback=True
        )

        # Get the newly created joke
        this_joke = BasicJokesResourceTestCase.get_joke_object(
            user_id=self.identity,
            content=app.config['FAKE_JOKE']
        )

        # Check if the newly created joke is present in the Joke table
        # and response code is 201 Created
        self.assertTrue(this_joke)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, b'Joke created')

        # Remove the fake joke from the Joke table
        BasicJokesResourceTestCase.delete_joke(
            user_id=self.identity,
            content=app.config['FAKE_JOKE']
        )

    def test_fail_on_submitting_humongous_string(self):
        """
        Test if submitting large text (> 900 chars)
        yields 400 Bad Request
        """
        response = BasicJokesResourceTestCase.create_joke(
            content=self.humongous_string,
            access_token=self.access_token,
            feedback=True
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, app.config['TOO_LONG'])

    def test_attempt_create_same_joke_twice(self):
        """
        In order to prevent the User from overfeeding
        the table, we make sure a User cannot create the
        same Joke twice
        :return:
        """

        # Create Joke
        BasicJokesResourceTestCase.create_joke(
            content=app.config['FAKE_JOKE'],
            access_token=self.access_token,
            feedback=True
        )

        # Attempt create Joke again
        response = BasicJokesResourceTestCase.create_joke(
            content=app.config['FAKE_JOKE'],
            access_token=self.access_token,
            feedback=True
        )

        self.assertEqual(response.status_code, 403)

    def test_fail_on_omitting_content(self):
        """
        Test if omitting 'content' in request parameters
        yields 400 Bad Request
        """
        response = tester.put('/create-joke', headers=dict(
            Authorization='Bearer ' + self.access_token)
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, b'No joke content present')

    def tearDown(self):
        RegistrationResourceTestCase.delete_user(
            username=app.config['JOKE_FAKE_USER']
        )


class RetrieveJokeTestCase(unittest.TestCase):
    """
    Test retrieving jokes from protected endpoint
    Test-case 1: attempt get joke with existing joke_id
    Test-case 2: attempt get joke with non-existing joke_id
    Test-case 3: attempt get joke without passing joke_id
    """

    access_token = None
    user_id = None

    @staticmethod
    def get_joke_by_id(joke_id, access_token):
        """
        Check if joke exists
        :param joke_id: said Joke's joke_id
        :param access_token: User's JWT
        :return: Response
        """
        response = tester.get('/get-joke-by-id', data=dict(
            joke_id=joke_id), headers=dict(
            Authorization='Bearer ' + access_token))
        return response

    def setUp(self):
        """
        Spawning one User and one Joke
        :return:
        """

        self.access_token = LoginTestCase.quick_setup_fake_user(
            username=app.config['FAKE_USER'],
            password=app.config['FAKE_USER_PASSWORD']
        )

        self.user_id = RegistrationResourceTestCase.get_user_id(
            app.config['FAKE_USER']
        )

        BasicJokesResourceTestCase.create_joke(
            content=app.config['FAKE_JOKE'],
            access_token=self.access_token
        )

    def test_retrieve_joke_content_by_existing_id(self):
        """
        Try getting Joke content by requesting one with proper joke_id
        :return: 200 OK, 'bytes' content
        """
        response = RetrieveJokeTestCase.get_joke_by_id(
            joke_id=1, access_token=self.access_token
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, bytes(
                         BasicJokesResourceTestCase.get_joke_object(
                             user_id=self.user_id,
                             content=app.config['FAKE_JOKE'],
                         ).content.encode('utf-8')))

    def test_fail_attempt_to_retrieve_joke_by_wrong_id(self):
        """
        Try getting Joke content by deliberately passing wrong joke_id
        :return: 404 Not Found
        """
        response = RetrieveJokeTestCase.get_joke_by_id(
            joke_id=10, access_token=self.access_token
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data, b'Nothing found')

    def test_fail_attempt_to_retrieve_joke_without_id(self):
        """
        Try getting Joke content by deliberately omitting joke_id parameter
        :return: 400 Bad Request
        """
        response = RetrieveJokeTestCase.get_joke_by_id(
            joke_id=None, access_token=self.access_token
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, b'joke_id is a required parameter')

    def tearDown(self):
        BasicJokesResourceTestCase.delete_joke(
            user_id=RegistrationResourceTestCase.get_user_id(
                app.config['FAKE_USER']
            ),
            content=app.config['FAKE_JOKE']
        )
        RegistrationResourceTestCase.delete_user(
            username=app.config['FAKE_USER']
        )


class GetAllJokeOfUserTestCase(unittest.TestCase):
    """
    Test retrieving all User's jokes
    Test-case 1: User has jokes, request to retrieve
    Test-case 2: User has no jokes, request to retrieve
    """

    access_token = None
    user_id = None

    def setUp(self):
        """
        Spawning one fake User and two Jokes
        For that, reuse the RJTC set_up() routine
        :return: None
        """
        retrieve_joke_test_case_object = RetrieveJokeTestCase()
        retrieve_joke_test_case_object.setUp()

        self.access_token = retrieve_joke_test_case_object.access_token
        self.user_id = retrieve_joke_test_case_object.user_id

        BasicJokesResourceTestCase.create_joke(
            content=app.config['ANOTHER_FAKE_JOKE'],
            access_token=self.access_token
        )

    @staticmethod
    def get_user_joke_count(user_id) -> int:
        """
        Return the number of Jokes that belong to User
        :param user_id: User's id
        :return: int: number of User's jokes
        """
        with app.app_context():
            all_jokes = Joke.query.filter_by(
                user_id=user_id
            ).all()
        return len(all_jokes)

    def test_retrieve_all_jokes_of_user_if_user_has_jokes(self):
        """
        This User has two jokes, test if endpoint returns them
        and status is 200 OK
        :return: jokes: application/json, 200 OK
        """
        response = tester.get('/my-jokes', headers=dict(
            Authorization='Bearer ' + self.access_token))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data)

    def test_retrieve_all_jokes_of_user_if_user_has_no_jokes(self):
        """
        This User has no jokes, test if request to the endpoint
        returns 204 No Content
        :return: 204 No Content
        """
        DeleteJokeTestCase.delete_all_user_jokes(self.user_id)

        response = tester.get('/my-jokes', headers=dict(
            Authorization='Bearer ' + self.access_token))

        self.assertEqual(response.status_code, 204)

    def tearDown(self):
        RegistrationResourceTestCase.delete_user(
            username=app.config['FAKE_USER']
        )


class UpdateJokeTestCase(unittest.TestCase):
    """
    Test patching user's jokes
    Test-case 1: Joke exists, let's patch it
    Test-case 2: Joke does not exist, but patch it
    Test-case 3: Request to patch Joke but do not pass its joke_id
    Test-case 4: Request to patch existing Joke with huge string
    """

    @staticmethod
    def send_patch(joke_id, access_token, content):
        return tester.patch('/update-joke',
                            data=dict(
                                joke_id=joke_id,
                                content=content
                            ),
                            headers=dict(
                                Authorization='Bearer ' + access_token))

    def setUp(self):
        get_all_jokes_object = GetAllJokeOfUserTestCase()
        get_all_jokes_object.setUp()

        self.access_token = get_all_jokes_object.access_token
        self.user_id = get_all_jokes_object.user_id

    def test_patching_existing_joke(self):
        """
        We presume that User has two non-identical jokes
        First, we assert that Joke.content by joke_id 1
        is not equal to ANOTHER_FAKE_JOKE
        :return: 204 No Content
        """

        self.assertNotEqual(
            BasicJokesResourceTestCase.get_joke_object(
                user_id=self.user_id,
                by_joke_id=1,
                content=app.config['ANOTHER_FAKE_JOKE']
            ).content,
            app.config['ANOTHER_FAKE_JOKE'])

        # Here we modify Joke.content by joke_id 1
        # to match ANOTHER_FAKE_JOKE
        response = UpdateJokeTestCase.send_patch(
            joke_id=1,
            access_token=self.access_token,
            content=app.config['ANOTHER_FAKE_JOKE']
        )

        self.assertEqual(response.status_code, 204)

        # Here we assert that Joke.content by joke_id 1
        # is now equal to ANOTHER_FAKE_JOKE
        self.assertEqual(
            BasicJokesResourceTestCase.get_joke_object(
                user_id=self.user_id, by_joke_id=1
            ).content,
            app.config['ANOTHER_FAKE_JOKE'])

    def test_attempt_to_patch_nonexistent_joke(self):
        response = UpdateJokeTestCase.send_patch(
            joke_id=3,
            access_token=self.access_token,
            content=app.config['ANOTHER_FAKE_JOKE']
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data, b'Nothing to patch')

    def test_attempt_to_patch_without_content(self):
        response = UpdateJokeTestCase.send_patch(
            joke_id=1,
            access_token=self.access_token,
            content=None
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, b'joke_id and content are required')

    def test_attempt_to_patch_with_humongous_string(self):
        response = UpdateJokeTestCase.send_patch(
            joke_id=1,
            access_token=self.access_token,
            content=BasicJokesResourceTestCase.humongous_string
        )

        with app.app_context():
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.data, app.config['TOO_LONG'])

    def tearDown(self):
        DeleteJokeTestCase.delete_all_user_jokes(self.user_id)
        RegistrationResourceTestCase.delete_user(
            username=app.config['FAKE_USER']
        )


class DeleteJokeTestCase(unittest.TestCase):
    """
    Test deletion of Jokes
    Test-case 1: Joke exists, delete it
    Test-case 2: Joke does not exist, but delete it
    Test-case 3: Request to delete Joke but do not pass its joke_id
    """
    access_token = None
    user_id = None

    def setUp(self):

        retrieve_joke_test_case_object = RetrieveJokeTestCase()
        retrieve_joke_test_case_object.setUp()

        self.access_token = retrieve_joke_test_case_object.access_token
        self.user_id = retrieve_joke_test_case_object.user_id

    @staticmethod
    def delete_all_user_jokes(user_id):
        """
        This method allows for deletion of all
        jokes than belong to User
        :param user_id: User's id
        :return: None
        """
        with app.app_context():
            for joke in Joke.query.filter_by(user_id=user_id).all():
                db.session.delete(joke)
            db.session.commit()

    @staticmethod
    def delete_joke_by_joke_id(joke_id, access_token):
        """
        This method allows for deletion of jokes by id
        :param joke_id: Joke joke_id
        :param access_token: User's JWT access token
        :return: Response
        """
        response = tester.delete('/delete-joke', data=dict(
            joke_id=joke_id), headers=dict(
            Authorization='Bearer ' + access_token)
        )
        return response

    def test_attempt_delete_existing_joke(self):
        """
        First, assert that User has one Joke
        Second, request deleting that Joke
        Third, assert that User has no Jokes
        Finally, assert that response is 200 OK
        and the Joke content is in the Response data
        :return: 200 OK
        """

        # Assert that newly created Joke is in Joke table
        self.assertNotEqual(GetAllJokeOfUserTestCase.get_user_joke_count(
            self.user_id), 0)

        # Get the newly added Joke content
        this_joke = BasicJokesResourceTestCase.get_joke_object(
            user_id=self.user_id, by_joke_id=1
        ).content

        # Request deleting the newly created Joke
        response = DeleteJokeTestCase.delete_joke_by_joke_id(
            joke_id=1, access_token=self.access_token
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, bytes(this_joke.encode('utf-8')))
        self.assertEqual(GetAllJokeOfUserTestCase.get_user_joke_count(
            self.user_id), 0)

    def test_attempt_delete_nonexistent_joke(self):
        """
        Attempt to delete a Joke that does not belong
        to the User
        :return: 404 Not Found
        """

        response = DeleteJokeTestCase.delete_joke_by_joke_id(
            joke_id=3, access_token=self.access_token
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data, b'This joke does not exist')

    def test_attempt_delete_joke_without_joke_id(self):
        """
        Attempt to delete a Joke without passing the joke_id
        :return: 400 Bad Request
        """

        response = DeleteJokeTestCase.delete_joke_by_joke_id(
            joke_id=None, access_token=self.access_token
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, b'joke_id is required')

    def tearDown(self):
        try:
            DeleteJokeTestCase.delete_all_user_jokes(self.user_id)
        except UnmappedInstanceError:
            pass


class TestImportJokeTestCase(unittest.TestCase):
    """
    Test importing jokes from foreign APIs
    Test-case 1: Import Joke from existing source
    Test-case 2: Import Joke from unknown source
    """

    access_token = None

    def setUp(self):

        self.access_token = LoginTestCase.quick_setup_fake_user(
            username=app.config['FAKE_USER'],
            password=app.config['FAKE_USER_PASSWORD']
        )

    def test_importing_from_supported_source(self):
        """
        Import a Joke from geek jokes
        :return: None
        """
        response = tester.put('/import-joke', data=dict(source='geek-jokes'),
                              headers=dict(
            Authorization='Bearer ' + self.access_token)
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, b'Joke created')

        DeleteJokeTestCase.delete_all_user_jokes(
            user_id=RegistrationResourceTestCase.get_user_id(
                app.config['FAKE_USER']
            )
        )

    def test_importing_from_unsupported_source(self):
        response = tester.put('/import-joke', data=dict(source='unknown-api'),
                              headers=dict(
            Authorization='Bearer ' + self.access_token)
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data, b'This source is not supported')


if __name__ == '__main__':
    unittest.main()
