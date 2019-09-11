from flask import (Flask, 
                   render_template,
                   request,
                   redirect,
                   url_for,
                   flash,
                   jsonify)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

# New imports for this step
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

engine = create_engine('sqlite:///category_item.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            return redirect('/login')
    return decorated_function


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    """
        Logs out the user and disconnects from the provider
        Login sesiion for the user is reset
        Then returns the user to home page
    """

    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
        Called when User tries to login through Facebook
        Once the login is successful-
            1. State token is validated
            2. user data is fetched from Facebook
               and store in login_session object
    """

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ("https://graph.facebook.com/oauth/access_token?"
           + "grant_type=fb_exchange_token&client_id=%s" % (app_id)
           + "&client_secret=%s&fb_exchange_token=%s" % (app_secret,
                                                         access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("result = %s" % result)

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace
        the remaining quotes with nothing so that it can be used directly
        in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')
    print(token)

    url = ("https://graph.facebook.com/v2.8/me?"
           + "access_token=%s&fields=name,id,email" % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("url sent for API access:%s" % url)
    print("API JSON result: %s" % result)
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = ("https://graph.facebook.com/v2.8/me/picture?"
           + "access_token=%s&redirect=0&height=200&width=200" % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
                           -webkit-border-radius: 150px;-moz-border-radius: \
                           150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """
        Revoke a current user's token
    """

    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ("https://graph.facebook.com/"
           + "%s/permissions?access_token=%s" % (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/login/')
def showLogin():
    """
        Create anti-forgery state token
        Then redirect the user to login page
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
        Called when User tries to login through Google
        Once the login is successful-
            1. State token is validated
            2. user data is fetched from Google
               and store in login_session object
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is \
                                            already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
                           -webkit-border-radius: 150px;-moz-border-radius: \
                           150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


def createUser(login_session):
    """
        Creates new user in the database
        Args:
            login_session: session object with user data
        Returns:
            user.id: generated distinct integer value identifying
                     the new user created
    """

    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
        Returns user item based on user id
        Args:
            user_id: distinct integer value given to each user
        Returns:
            user: user associated with the user_id as stored
            in the User database
    """

    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
        Returns user item based on user's email
        Args:
            email: distinct email associated with each user
        Returns:
            if email is not associated with any user then None is returned
            otherwise user associated with the email is returned
            as stored in the User database
    """

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception as e:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    """
        Revoke a current user's token and reset their login_session
    """

    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user \
                                            not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke \
                                            token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@app.route('/categories/')
def showCategories():
    """
        This is the home page
        It lists all the Categories on the left
        5 most recently added items are also listed
        There is an option to Login as well
    """

    categories = session.query(Category)
    latest_items = session.query(Item).order_by(Item.id.desc()).limit(5)
    latest_items_categories = [session.query(Category).
                               filter_by(id=i.category_id).one().name
                               for i in latest_items]
    return render_template('categories.html',
                           categories=categories,
                           latest_items=latest_items,
                           lic=latest_items_categories,
                           length=latest_items.count())


@app.route('/categories/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
        Add a new Category to the database
        Args:
            On GET: Returns the page for adding a new category
            On POST: Redirect to home after category is created
            Login page when user is not signed in
    """

    if request.method == 'POST':
        newItem = Category(name=request.form['name'],
                           user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("new category created!")
        return redirect(url_for("showCategories"))
    else:
        return render_template('newCategory.html')


@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    """
        Edit an existing Category in the database
        Args:
            On GET: Returns the page for editing the category
            On POST: Redirect to home after category has been edited
            Login page when user is not signed in
            Error page when user is not authorized to edit
    """

    editedItem = session.query(Category).filter_by(id=category_id).one()
    if editedItem.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert"
                + "('You are not authorized to edit this category. "
                + "Please create your own category in order to edit.');}"
                + "</script><body onload='myFunction()''>")

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        session.add(editedItem)
        session.commit()
        flash("Category edited!")
        return redirect(url_for("showCategories"))
    else:
        return render_template('editCategory.html', category=editedItem)


@app.route('/categories/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    """
        Delete an existing Category in the database
        Args:
            On GET: Returns the page for deleting the category
            On POST: Redirect to home after category has been edited
            Login page when user is not signed in
            Error page when user is not authorized to delete
    """

    deletedItem = session.query(Category).filter_by(id=category_id).one()
    if deletedItem.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert"
                + "('You are not authorized to delete this category. "
                + "Please create your own category in order to delete.');}"
                + "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        flash("Category deleted!")
        return redirect(url_for("showCategories"))
    else:
        return render_template('deleteCategory.html', category=deletedItem)


@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def showItems(category_id):
    """
        Displays the items present within a category
    """

    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category.id)
    categories = session.query(Category)
    return render_template('Items.html', category=category,
                           categories=categories, items=items)


@app.route('/categories/<int:category_id>/items/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_id):
    """
        Add a new item to the database
        Args:
            On GET: Returns the page for adding a new item
            On POST: Redirect to home after item is created
            Login page when user is not signed in
    """
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category_id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("new item created!")
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('newItem.html', category_id=category_id)


@app.route('/categories/<int:category_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editItem(category_id, item_id):
    """
        Edit an existing Item in the database
        Args:
            On GET: Returns the page for editing the item
            On POST: Redirect to home after item has been edited
            Login page when user is not signed in
            Error page when user is not authorized to edit
    """

    editedItem = session.query(Item).filter_by(id=item_id).one()
    if editedItem.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert"
                + "('You are not authorized to edit this item. "
                + "Please create your own item in order to edit.');}"
                + "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash("item edited!")
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template(
            'editItem.html', category_id=category_id, item_id=item_id,
            item=editedItem)


@app.route('/categories/<int:category_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_id, item_id):
    """
        Delete an existing item in the database
        Args:
            On GET: Returns the page for deleting the item
            On POST: Redirect to home after item has been edited
            Login page when user is not signed in
            Error page when user is not authorized to delete
    """

    deletedItem = session.query(Item).filter_by(id=item_id).one()
    if deletedItem.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert"
                + "('You are not authorized to delete this item. "
                + "Please create your own item in order to delete.');}"
                + "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        flash("item deleted!")
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template(
            'deleteItem.html', item=deletedItem)


@app.route('/categories/JSON/')
def categoryJSON():
    """ Returns Categories info in JSON format"""

    categories = session.query(Category)
    return jsonify(categories=[i.serialize for i in categories])


@app.route('/categories/<int:category_id>/items/JSON/')
def categoryItemsJSON(category_id):
    """ Returns items info in a particular category in JSON format"""

    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000, threaded=False)
