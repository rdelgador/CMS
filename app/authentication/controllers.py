from flask import (
    Blueprint,
    request,
    render_template,
    flash,
    g,
    session,
    redirect,
    url_for
)
from werkzeug import check_password_hash, generate_password_hash

from app import db, mail
from app.authentication.forms import LoginForm, SignupForm, RecoverPassForm, ResetPasswordSubmit
from app.authentication.models import User
from flask.ext.security.utils import encrypt_password, verify_password
from flask_mail import Mail, Message



mod_auth = Blueprint('auth', __name__, url_prefix='/auth')

@mod_auth.route('/profile')
def profile():

    if 'email' not in session:
        return redirect(url_for('signin'))

    user = User.query.filter_by(email = session['email']).first()

    if user is None:
        return redirect(url_for('signin'))
    else:
        return render_template('authentication/profile.html')

@mod_auth.route('/signup/', methods=['GET', 'POST'])
def signup():

    form = SignupForm()

    if 'email' is session:
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        if form.validate() == False:
            return render_template("authentication/signup.html", form=form)
        else:
            new_user = User(form.username.data, form.email.data, form.password.data)
            db.session.add(new_user)
            db.session.commit()

            session['email'] = new_user.email
            return "Not found"
        
    elif request.method == 'GET':
        return render_template("authentication/signup.html", form=form)


@mod_auth.route('/signin/', methods=['GET', 'POST'])
def signin():

    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('Welcome %s' % user.name)
            return redirect(url_for('auth.home'))

        flash('Wrong email or password', 'error-message')

    return render_template("authentication/signin.html", form=form)

@mod_auth.route('/change_pass', methods=['GET','POST'])
def change_pass():
	token = request.args.get('token',None)
	verified_result = User.verify_token(token)
	if token and verified_result:
		print verified_result
		password_submit_form = ResetPasswordSubmit(request.form)

		if password_submit_form.validate_on_submit():
			verified_result.password = generate_password_hash(password_submit_form.password.data)
			db.session.commit()
			flash("password updated successfully")
			return redirect('users')
		return render_template("change_pass.html",form=password_submit_form)