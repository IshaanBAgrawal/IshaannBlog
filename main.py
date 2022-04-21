from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ContactForm
from flask_gravatar import Gravatar
from functools import wraps
import smtplib
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6doneWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CREATE LOGI MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# Initialise Gravatar
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    # relationship with Comment
    comments = relationship('Comment', back_populates='author')

    # relationship with BlogPost
    posts = relationship('BlogPost', back_populates='author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # relationship with User
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # relationship with Comments
    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    #  relationship with User
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='comments')

    # relationship with BlogPost
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')

    comment = db.Column(db.String, nullable=False)


# db.create_all()

# USER LOADER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CHECK WHETHER USER IS ADMIN
def current_user_status_check():
    current_user_status = 'user'
    if current_user.is_authenticated and current_user.id == 1:
        current_user_status = 'admin'
    return current_user_status


# SEND MAIL
def send_mail(message, to_address_mail):
    my_email = os.environ.get('COMPANY_EMAIL')
    password = os.environ.get('COMPANY_EMAIL_PASS')
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        connection.sendmail(
            from_addr=my_email,
            to_addrs=to_address_mail,
            msg=message,
        )


# ADMIN RESTRICTING DECORATOR
def admin_only(function):
    @wraps(function)
    def admin_function_inner(**kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            try:
                return function(kwargs['post_id'])
            except KeyError:
                return function()
        else:
            return abort(403)
    return admin_function_inner


# MAIN ROUTES
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check(), len=len)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).all():
            error = 'That email already exists. Please try to login.'
            return redirect(url_for('login', error=error))
        new_user = User(
            email=email,
            password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16),
            name=form.name.data,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, remember=True)
        flash('Registered Successfully.')
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check())


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = request.args.get('error')
    if error is None:
        error = ''
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        try:
            user_specified = load_user(User.query.filter_by(email=email).all()[0].id)
        except IndexError:
            error = 'We couldn\'t find an email with that account. Please try again.'
        else:
            password_entered_is_correct = check_password_hash(pwhash=user_specified.password, password=password)
            if password_entered_is_correct:
                login_user(user_specified, remember=True)
                flash('Logged in Successfully.')
                return redirect(url_for('get_all_posts'))
            else:
                error = 'The password you entered is incorrect. Please try again.'
    return render_template("login.html", form=form, error=error,
                           current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check())


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm(comment='')
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            error = 'Please login to make a comment.'
            return redirect(url_for('login', error=error))
        new_comment = Comment(
            comment=comment_form.comment.data,
            author=current_user,
            parent_post=requested_post,
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check(), comment_form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check())


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    contact_form = ContactForm()
    if not current_user.is_authenticated:
        error = 'Please login before trying to contact.'
        return redirect(url_for('login', error=error))
    if contact_form.validate_on_submit():
        name = current_user.name
        email = current_user.email
        phone_num = contact_form.phone_num.data
        msg = f"Subject: New User\n\n" \
              f"Name: {name}\n" \
              f"Email: {email}\n" \
              f"Phone: {phone_num}\n" \
              f"Messgae: {contact_form.message.data}"
        send_mail(msg, os.environ.get('PERSONAL_EMAIL'))
        new_msg = f"Subject: Thankyou for contacting me!\n\n" \
                  f"Dear {name},\n\n" \
                  f"This is Ishaan B. Agrawal, the owner of the site, \"Ishaan's Blogs\". I recently got your m" \
                  f"essage. If you have any problems, or have anything to say, I will contact you shortly."
        send_mail(new_msg, email)
        return redirect(url_for('get_all_posts'))
    return render_template("contact.html", current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check(), contact_form=contact_form)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        print('hi')
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check())


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user_authenticated=current_user.is_authenticated,
                           current_user_status=current_user_status_check())


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
