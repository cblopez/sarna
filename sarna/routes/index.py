from flask import Blueprint, render_template, request, flash

from sarna.auxiliary import redirect_back
from sarna.core.auth import login_required, logout_user
from sarna.core.security import limiter
from sarna.forms.auth import LoginForm
from sarna.model.user import User

blueprint = Blueprint('index', __name__)


@blueprint.route('/', methods=('GET', 'POST'))
@limiter.limit('10 per minute')
def index():
    form = LoginForm(request.form)
    context = dict(
        form=form,
        need_otp=False
    )

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            if not user.otp_enabled or user.otp_enabled and user.confirm_otp(form.otp.data):
                user.login()

                flash('Logged in successfully.', 'success')
                return redirect_back('index.index')

        if form.otp.data:
            flash('Invalid credentials', 'danger')
        else:
            form.otp.errors.append('Google Authenticator OTP required.')

        context['need_otp'] = True

    return render_template('index.html', **context)


@blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect_back('index.index')
