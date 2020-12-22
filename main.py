from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_ckeditor import CKEditor
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user, login_required
from datetime import date
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY')
ckeditor = CKEditor(app)

# DB CONNECTION
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///posts.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE POST DB TABLE
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.String(250), nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(250))


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        else:
            return f(*args, **kwargs)

    return decorated_function


all_posts = []

posts = BlogPost.query.all()

for post in posts:
    post_data = {
        "id": post.id,
        "title": post.title,
        "date": post.date,
        "subtitle": post.subtitle,
        "author": post.author,
        "body": post.body,
        "img_url": post.img_url
    }
    all_posts.append(post_data)


@app.route('/')
def home():
    return render_template('index.html',
                           blogs=all_posts,
                           total_blogs=len(all_posts),
                           logged_in=current_user.is_authenticated,
                           )


@app.route('/post/<int:index>')
def show_post(index):
    requested_post = None
    for blog_post in all_posts:
        if blog_post['id'] == index:
            requested_post = blog_post
    return render_template('post.html', post=requested_post)


@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def new_post():
    if request.method == 'POST':
        form_data = request.form
        post = BlogPost(
            title=form_data['make_post_title'],
            subtitle=form_data['make_post_subtitle'],
            author=form_data['make_post_author'],
            img_url=form_data['make_post_img_url'],
            body=form_data['make_post_body'],
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template('make-post.html', is_edit_post=False)


@app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = db.session.query(BlogPost).filter_by(id=post_id)
    if request.method == 'POST':
        form_data = request.form
        post.title = form_data['make_post_title']
        post.subtitle = form_data['make_post_subtitle']
        post.author = form_data['make_post_author']
        post.img_url = form_data['make_post_img_url']
        post.body = form_data['make_post_body'],
        post.date = date.today().strftime("%B %d, %Y")
        db.session.commit()
        return redirect(url_for(show_post(index=post.id)))
    return render_template('make-post.html', is_edit_post=True)


@app.route('/delete-post/<int:post_id>', methods=['GET'])
@admin_only
def delete_post(post_id):
    post = BlogPost.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/about')
def about_page():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact_page():
    return render_template('contact.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        register_data = request.form
        user_email = register_data.get('email')

        if User.query.filter_by(email=user_email).first():
            flash('You have already registered ! Try Log In ..')
            return redirect(url_for('login'))
        user_name = register_data.get('name')
        user_encry_pwd = generate_password_hash(
            register_data.get('password'),
            method='pbkdf2:sha256',
            salt_length=6
        )

        new_User = User(
            email=user_email,
            password=user_encry_pwd,
            name=user_name
        )

        db.session.add(new_User)
        db.session.commit()
        login_user(new_User)
        return redirect(url_for('home'))
    return render_template('register.html', logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_data = request.form
        user_email = login_data.get('email')
        user_password = login_data.get('password')
        found_user = User.query.filter_by(email=user_email).first()
        if not found_user:
            flash("No user Found ! Try again")
            return redirect(url_for('login'))
        elif not check_password_hash(found_user.password, user_password):
            flash("Email & Password mismatch ! Try Again ..")
            return redirect(url_for('login'))
        else:
            login_user(found_user)
            return redirect(url_for('home'))
    return render_template('login.html', logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
