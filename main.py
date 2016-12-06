#!/usr/bin/env python
#
# Copyright 2016 Jason Boyer
#
# This is the main python file for my blog application created using Google App
# Engine.
#
# Completed 8/22/2016
#

import webapp2
import os
import jinja2
import re
import time
import hashlib
import datetime

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)










###############################################################################

#                   Utility/Support classes and methods

###############################################################################


# Create a hash value that includes the original value along with its
# hash. Used to verify that cookies have not been tampered with.
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

# Simple hash method that creates an md5 hash from a string and a salt value
def hash_str(s):
    return hashlib.md5(s + "secretword").hexdigest()

# Method to test if a secure value and its hash are correct
def check_secure_val(h):
    test=h.split('|')
    if test[1] == make_secure_val(test[0]).split('|')[1]:
        return test[0]



# Database setup for the registration data.
class Users(db.Model):
    user_name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)


# Database setup for the article data.
class Entry(db.Model):
    title = db.StringProperty(required = True)
    article = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)
    like_count = db.IntegerProperty(default = 0)
    liked_by_list = db.StringListProperty(default = "")
    parent_post = db.IntegerProperty(required = True)

# Base handler class to simplify write and render operations for other methods.
# This class is from the Udacity Full Stack Developer Nanodegree, not created
# by me.
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))



# Class to validate form data
class ValidateForm():
    def validate(self, username,password,verify,email):
        response=""

        # Check each form item and create an error if it does not meet the
        # requirements.
        if self.check_name(username) is None:
            response += "Please enter a valid username. "

        if self.check_password(password) is None:
            response += "Please enter a valid password. "

        if self.check_password(verify) is None:
            response += "Please verify your password. "

        if self.check_match(password, verify) is None:
            response += "Passwords do not match. "

        if self.check_email(email) is None:
            response += "Please enter a valid email. "

        return response

    #Method to check the username against the requirements regex.
    def check_name(self, name):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(name)

    # Method to check if a password against the requirements regex.
    def check_password(self, password):
        PWD_RE = re.compile(r"^.{3,20}$")
        return PWD_RE.match(password)

    # Method to verify that password and confirmation passord match.
    def check_match(self, password, confirm):
        return password == confirm

    # Method to validate an email address against an email regex.
    def check_email(self, email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return email == "" or EMAIL_RE.match(email)


# Blog key for db consistency
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


# Utility class to validate user information and return a dictionary with
# information about the user.
class getKey():
    def with_post_id(self, post_id,username="",limit="",query=False,sameuser=True):
        if username and username != "":
            key = db.Key.from_path('Entry', int(post_id),parent=blog_key())
            data = db.get(key)
        else:
            self.redirect("/")
        results = {"username": check_secure_val(username),
                    "uid_w_key": username,
                    "data": data,
                    "post_id": post_id,
                    }
        if results["username"]== data.author:
            results["check_same_owner"]= True
        else:
            results["check_same_owner"]= False
        return results











###############################################################################

#                           USER ACCOUNT CLASSES

###############################################################################

# Class to verify user and email have not been registered. If they are new,
# create a new user in the database.
class CreateUser():
    def create(self, uid="",email="",pwd=""):
        # Check Database for existing user

        # Gql does not support OR statements in the WHERE clause, need two
        # separate queries to make sure both UID and email are not yet
        # registered.
        response = ""
        if uid !="" and pwd!="":
            data=db.GqlQuery("SELECT * FROM Users WHERE user_name = '" + uid + "'")
            data2=db.GqlQuery("SELECT * FROM Users WHERE email = '" + email + "'" + "and email != ''")

            # Check if UID has been registered
            if data.get():
                response += "User ID already exists" + str(data.get().user_name)

            # Check if email has been registered
            if data2.get():
                response += "Email already registered" + str(data2.get().email)

            # Add new user if no errors have been identified
            if response=="":
                # Hash and store the UID and password
                a = Users(user_name=hash_str(uid), password = hash_str(pwd), email = email)
                key = a.put()
                if not key:
                    response += "Error adding to database"
        else:
            response += "Error adding to database"

        return response



# This is the handler for the registration page. It is responsible for form
# validation, rejecting duplicate IDs or emails, and registering the user if
# all requirements are satisfied.
class SignUpHandler(Handler):
    def get(self):
        self.render("signup.html", response = "")

    def post(self):
        response = ""

        # Get each form value
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        # Test each form value for validity, update error message if any errors
        # exist.
        response = ValidateForm().validate(username = username,
                                        password = password,
                                        verify = verify,
                                        email = email)

        # If no error message, ok to proceed with validating and creating a
        # user account.
        if response == "":
            response = CreateUser().create(uid=username,
                                        email=email,
                                        pwd=password)
            self.render("signup.html", response = response)
        if response=="":
            # Set a cookie with the new user ID and its hash
            self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % str(make_secure_val(username)))

        # If no errors, redirect to the welcome page. Otherwise show signup
        # page and any errors.
        if response == "":
            self.redirect('/welcome')
        else:
            self.render("signup.html", response = response)



# Class for validating user id
class LoginHandler(Handler):
    def get(self):
        # If user is already logged in, redirect them to welcome page
        username = self.request.cookies.get('name')
        if username and username!="":
            self.redirect("/welcome")
        else:
            self.render("login.html", response = "")

    def post(self):
        # Check Database for existing user

        # Gql does not support OR statements in the WHERE clause, need two
        # separate queries to make sure both UID and email are not yet
        # registered.

        response = ""
        uid=self.request.get('username')
        pwd=self.request.get('password')

        if uid !="" and pwd!="":

            # UID must be hashed because it is stored as a hash value in the
            # database.
            data=db.GqlQuery("SELECT * FROM Users WHERE user_name = '" + hash_str(uid) + "'")

            # If there was an entry for the UID attempt to log in
            if data.get():
                if hash_str(uid) == data.get().user_name:
                    if hash_str(pwd) == data.get().password:
                        self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % str(make_secure_val(uid)))
                        self.redirect('/welcome')
                    else:
                        response += "Incorrect password"
            else:
                self.redirect('/signup')
        else:
            response += "Please enter a username and passowrd"

        self.render("login.html",response=response)



# Class for validating user id
class LogoutHandler(Handler):
    def get(self):
        # If user is already logged in, log them out then redirect them to login page. If not logged in, automatically redirect them to the login page.
        username = self.request.cookies.get('name')
        if username and username != "":
            self.response.headers.add_header('Set-Cookie', 'name=; Path=/;')
            self.response.headers.add_header('Set-Cookie', 'referrer_url=; Path=/')
        self.redirect("/login")











###############################################################################

#                     General page rendering classes

###############################################################################



# Class for rendering the welcome page, checks for a valid cookie and if one
# does not exist, redirects to the signup page.
class WelcomeHandler(Handler):
    def get(self):
        # Get username from cookie and check that 1) the cookie exists and
        # 2) it is not a blank value, send to login page otherwise.
        username = self.request.cookies.get('name')
        if username and username!="":
            self.render("welcome.html", username = check_secure_val(username))
        else:
            self.redirect('/signup')


# Class to render the frontpage of the site
class MainHandler(Handler):
    def get(self, title="", article="", error="",author=""):
        # User can view the webpage if not logged in so do not require uid but
        # a value needs to be set so that main.html can display a login link if
        # no uid, or can display the username if logged in.
        username = self.request.cookies.get('name')
        # Set cookie to enable canceled edits to return here
        self.response.headers.add_header('Set-Cookie', 'referrer_url=%s; Path=/' % self.request.url)
        if not username:
            username = ""
        elif check_secure_val(username):
            username= check_secure_val(username)
        articles = db.GqlQuery("SELECT * FROM Entry "
                            "WHERE parent_post = 0 "
                            "ORDER BY created DESC LIMIT 10")
        self.render("main.html",title=title, article=article, error=error, articles = articles,author=author, username=username)










###############################################################################

#           Post Manipulation Classes (Post, Edit, Like, Delete, etc)

###############################################################################



# Class to create and render a new post while displaying the 10 most recent
# posts.
class NewPostHandler(Handler):
    def get(self, title="", article="", error="",author="",articles="",
        username=""):
        # Get username from cookie and check that 1) the cookie exists and
        # 2) it is not a blank value, send to login page otherwise.
        username = self.request.cookies.get('name')
        if username and username != "":
            articles = db.GqlQuery("SELECT * FROM Entry "
                            "WHERE parent_post = 0 "
                            "ORDER BY created DESC LIMIT 10")
            self.render("newpost.html",title=title, article=article,
                error=error, articles = articles, author=author, username=check_secure_val(username))
        else:
            self.redirect('/login')

    def post(self):
        title = self.request.get("subject")
        article = self.request.get("content")
        username = check_secure_val(self.request.cookies.get('name'))

        # Get username from cookie and check that 1) the cookie exists and
        # 2) it is not a blank value, send to login page otherwise.
        if username and username != "":
            if title and article:
                a = Entry(title=title, article=article, parent=blog_key(),
                    author=username, parent_post = 0)
                a.put()
                self.redirect("/post/" + str(a.key().id()))
            else:
                error = "You need to include both a title and an article"
                self.render_front(title,article,error)
        else:
            redirect("/login")




# Class to redirect user to their new post once they create it.
class PostHandler(Handler):
    def get(self, post_id):
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        username = self.request.cookies.get('name')
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="")
        title= keyinfo["data"].title
        article= keyinfo["data"].article
        date= keyinfo["data"].created.date().strftime('%A, %B %d, %Y')
        author = keyinfo["data"].author
        self.render("postpermalink.html", title=title,article=article,
            date=date, author=author,username=keyinfo["username"])



# Class to handle editing of posts
class EditHandler(Handler):
    def get(self):
        url = self.request.url
        post_id = url.rsplit('/', 1)[-1]
        username = self.request.cookies.get('name')
        self.response.headers.add_header('Set-Cookie',
            'post_id=%s; Path=/' % str(post_id))
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="")
        # Check if current user is the author of the post and if so allow them
        # to edit the post.
        if keyinfo["username"] == keyinfo["data"].author:
            title= keyinfo["data"].title
            article= keyinfo["data"].article
            date= keyinfo["data"].created.date().strftime('%A, %B %d, %Y')
            author = keyinfo["data"].author

            self.render("editpost.html", title=title,article=article,
                date=date, author=author, id=post_id,
                username=keyinfo["username"])
        else:
            error = "Only the author of the article may edit it"
            self.render("error.html",error=error)

    def post(self):
        article = self.request.get("content")
        post_id = self.request.cookies.get('post_id')
        username = self.request.cookies.get('name')
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="")
        keyinfo["data"].article = article
        keyinfo["data"].put()
        #Sleep for one second before redirecting and updating the post
        time.sleep(1)
        self.redirect(self.request.referer)


class EditCancelHandler(Handler):
    def get(self):
        url = self.request.cookies.get('referrer_url')
        self.redirect(str(url))



# Class for liking a post
class LikeHandler(Handler):
    def get(self,post_id):
        username = self.request.cookies.get('name')
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="")
        # Cannot like a post if it is their own post
        if keyinfo["check_same_owner"]:
            error = ("You may only like or unlike posts that you did not"
                     "create")
            self.render("error.html",error=error,
                username=check_secure_val(username))
        # If they are not the owner, and they have not already liked the post
        # then allow to like. Sleep for 1 second to allow update.
        elif keyinfo["username"] not in keyinfo["data"].liked_by_list:
            keyinfo["data"].like_count = keyinfo["data"].like_count + 1
            keyinfo["data"].liked_by_list.append(keyinfo["username"])
            keyinfo["data"].put()
            time.sleep(1)
            self.redirect(self.request.referer)
        else:
            self.redirect(self.request.referer)


# Class for unliking a post
class UnLikeHandler(Handler):
    def get(self,post_id):
        username = self.request.cookies.get('name')
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="")
        # Cannot unlike a post if it is their own post
        if keyinfo["check_same_owner"]:
            error = ("You may only like or unlike posts that you did not"
                     "create")
            self.render("error.html",error=error,username=keyinfo["username"])
        # If they are not the owner, and they have already liked the post
        # then allow to like. Sleep for 1 second to allow update.
        elif keyinfo["username"] in keyinfo["data"].liked_by_list:
            if keyinfo["data"].like_count>0: # This should not matter but just
                                  # in case a situation occurs where a user
                                  # name is in the liked list and the count
                                  # had not been properly decremented.
                keyinfo["data"].like_count = keyinfo["data"].like_count - 1
                keyinfo["data"].liked_by_list.remove(keyinfo["username"])
                keyinfo["data"].put()
                time.sleep(1)
            self.redirect(self.request.referer)
        else:
            self.redirect(self.request.referer)



# Class for adding comments to posts
class CommentHandler(Handler):
    def get(self, title="", article="", error="",author="" ):
        url = self.request.url
        post_id = url.rsplit('/', 1)[-1]
        username = self.request.cookies.get('name')
        # Set cookie to enable canceled edits to return here
        #self.response.headers.add_header('Set-Cookie', 'referrer_url=%s; Path=/' % self.request.url)
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="")
        mainarticle = keyinfo["data"]
        articles = db.GqlQuery("SELECT * FROM Entry "
                        "WHERE parent_post = " + post_id +
                        "ORDER BY created DESC LIMIT 10")
        self.render("comment.html",title=title, article=article, error=error,
                articles = articles, author=author, mainarticle= mainarticle,
                username = keyinfo["username"])

    def post(self):
        title = self.request.get("subject")
        article = self.request.get("content")
        parentid = self.request.get("parentid")
        username = check_secure_val(self.request.cookies.get('name'))

        # Check user login status and createa new article with the information
        # from the form.
        if username and username != "":
            if title and article:
                a = Entry(title=title, article=article, parent=blog_key(),
                    author=username, parent_post = int(parentid))
                a.put()
                self.redirect("/postcomment/" + str(parentid))
            else:
                error = "You need to include both a title and an article"
                self.render("error.html",error=error,
                            username=check_secure_val(username))
        else:
            redirect("/login")


# Class for displaying post comments.
class PostCommentHandler(Handler):
    def get(self, post_id, title="", article="", error="",author="",
            username="" ):
        username = self.request.cookies.get('name')
        # Set cookie to enable canceled edits to return here
        self.response.headers.add_header('Set-Cookie', 'referrer_url=%s;'
            'Path=/' % self.request.url)
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="")
        article = keyinfo["data"]
        articles = db.GqlQuery("SELECT * FROM Entry "
                        "WHERE parent_post = " + post_id +
                        "ORDER BY created DESC LIMIT 10")
        self.render("displaypost.html",title=title, article=article,
                error=error, articles = articles, author=author,
                rootID=post_id, username=check_secure_val(username))



# Class for deleting posts
class DeletePostHandler(Handler):
    def get(self,post_id):
        username = self.request.cookies.get('name')
        # Get username from cookie, validation and redirection(if needed), is
        # handled in the getKey() class.
        keyinfo = getKey().with_post_id(post_id=post_id,username=username,
            limit="", sameuser=True)
        # Make sure owner of the post is deleting it.
        if keyinfo["check_same_owner"]:
            # Even though the owner of the post may not be the owner of
            # comments to the post, the comments will be left "floating" in the
            # database if the post is deleted, so delete all comments too.
            articles = db.GqlQuery("SELECT * FROM Entry "
                        "WHERE parent_post = " + post_id)
            for article in articles:
                article.delete()
            # Delete the main post
            keyinfo["data"].delete()
            time.sleep(1)
            self.redirect("/")
        else:
            error="You do not have permission to delete this post."
            self.render("error.html",error=error,username=keyinfo["username"])


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomeHandler),
    ('/signup', SignUpHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/newpost', NewPostHandler),
    (r'/post/([0-9]+)', PostHandler),
    (r'/editpost/[0-9]+', EditHandler), # Parenthesis removed to avoid issue with Posting
    (r'/like/([0-9]+)', LikeHandler),
    (r'/unlike/([0-9]+)', UnLikeHandler),
    (r'/comment/[0-9]+', CommentHandler), # Parenthesis removed to avoid issue with Posting
    (r'/postcomment/([0-9]+)', PostCommentHandler),
    (r'/deletepost/([0-9]+)', DeletePostHandler),
    ('/canceledit',EditCancelHandler)
], debug=True)
