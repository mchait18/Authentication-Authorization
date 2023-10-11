from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import UserForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///auth_assignment"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.app_context().push()

connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def home_page():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if 'username' in session:
        username = session['username']
        return redirect (f'/users/{username}')
    
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username, password, email, first_name, last_name)

        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken. Please pick another')
            return render_template('register.html', form=form)
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect (f'/users/{username}')
    
    return render_template('users/register.html', form=form)

@app.route('/login', methods=["GET", 'POST'])
def login_user():
    if 'username' in session:
        username = session['username']
        return redirect (f'/users/{username}')
    form=LoginForm()
    if form.validate_on_submit():
        username=form.username.data
        password=form.password.data

        user=User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['username'] = user.username
            return redirect(f'/users/{username}')
        else:
            form.username.errors = ['Invalid username/password.']
    
    return render_template ('users/login.html', form=form)

@app.route('/users/<username>')
def get_user(username):
    if 'username' in session and session['username'] == username:
        user=User.query.get(username)
        feedback = Feedback.query.filter_by(username=username)
        return render_template('users/user.html', user=user, feedback=feedback)
    
    flash("Please login first!", "danger")
    return redirect ('/login')

@app.route('/users/<username>/delete', methods=["GET", "POST"])
def delete_user(username):
    """Delete User if logged in"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect ('/login') 
    
    if session['username'] == username:
        user= User.query.get_or_404(username)
        feedback=Feedback.query.filter_by(username=username)
        for f in feedback:
            db.session.delete(f)
        db.session.delete(user)
        db.session.commit()
        flash("User deleted!", "info")
        session.pop('username')
        return redirect ('/')
    flash("You don't have permission to do that!", "danger")
    return redirect(f'/users/{username}')


@app.route('/users/<username>/feedback/add', methods=["GET", 'POST'])
def add_feedback(username):
    if 'username' not in session or session['username'] != username:
        flash("Please login first!", "danger")
        return redirect ('/login')        
    form=FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_feedback = Feedback(title=title, content=content, username=username)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback Created!', 'success')
        return redirect(f'/users/{username}')
    
    return render_template('feedback/add.html', form=form)

@app.route('/feedback/<int:id>/update', methods=["GET", 'POST'])
def update_feedback(id):
    """update feedback"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect ('/login')   
    feedback=Feedback.query.get_or_404(id)
    if feedback.username == session['username']:  
        form=FeedbackForm(obj=feedback)
        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data
            username= session['username']
            db.session.commit()
            flash(f'Feedback "{feedback.title}" updated!', 'success')
            return redirect(f'/users/{username}')
    
        return render_template('feedback/edit.html', form=form)
    
    flash("You don't have permission to do that!", "danger")
    return redirect(f'/users/{username}')

@app.route('/feedback/<int:id>/delete', methods=["GET", "POST"])
def delete_feedback(id):
    """Delete Feedback if user is logged in"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect ('/login') 
    
    feedback=Feedback.query.get_or_404(id)
    if feedback.username == session['username']:                  
        db.session.delete(feedback)
        db.session.commit()
        flash("Feedback deleted!", "info")        
        return redirect (f'/users/{feedback.username}')
    flash("You don't have permission to do that!", "danger")
    return redirect(f'/users/{feedback.username}')


@app.route('/logout')
def logout_user():
    session.pop('username')
    flash("Goodbye!", "info")
    return redirect('/')

