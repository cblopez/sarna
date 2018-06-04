import os
from secrets import token_urlsafe

from flask import render_template, request
from werkzeug import exceptions

from sarna.core import csrf, limiter, app
from sarna.core import assets
from sarna.model import init_database, ObjectNotFound
from sarna.routes import clients, index, findings, users, assessments

init_database()


def error_handler(err):
    if request.headers.get('x-requested-with', '') == "XMLHttpRequest":
        return str(err), err.code

    if isinstance(err, ValueError):
        err = exceptions.BadRequest()
    elif isinstance(err, ObjectNotFound):
        err = exceptions.NotFound()

    context = dict(
        code=err.code,
        error=err.name,
        description=err.description,
    )
    return render_template('error.html', **context), context['code']


app.register_blueprint(index.blueprint)
app.register_blueprint(clients.blueprint, url_prefix='/clients')
app.register_blueprint(assessments.blueprint, url_prefix='/assessments')
app.register_blueprint(findings.blueprint, url_prefix='/findings')
app.register_blueprint(users.blueprint, url_prefix='/users')

app.register_error_handler(400, error_handler)
app.register_error_handler(401, error_handler)
app.register_error_handler(403, error_handler)
app.register_error_handler(404, error_handler)
app.register_error_handler(405, error_handler)
app.register_error_handler(408, error_handler)
app.register_error_handler(409, error_handler)
app.register_error_handler(413, error_handler)
app.register_error_handler(429, error_handler)
app.register_error_handler(500, error_handler)
app.register_error_handler(501, error_handler)
app.register_error_handler(502, error_handler)
app.register_error_handler(503, error_handler)
app.register_error_handler(504, error_handler)

if __name__ == '__main__':

    csrf.init_app(app)
    limiter.init_app(app)
    assets.init_app(app)

    app.config.update(
        DEBUG=True,
        WTF_CSRF_SECRET_KEY=token_urlsafe(64),
        SECRET_KEY=token_urlsafe(64),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10 Mb limit
        ASSETS_DEBUG=True
    )

    extra_files = ["templates"]
    for dirname, dirs, files in os.walk("templates"):
        for file in files:
            extra_files.append(os.path.join(dirname, file))

    app.run(
        '0.0.0.0',
        extra_files=extra_files
    )
