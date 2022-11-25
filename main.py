import os

from Crypto.PublicKey import RSA
from flask import Flask
from flask import flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask import render_template
from flask import redirect
from wtforms.fields import FileField
from wtforms.fields import SubmitField
from werkzeug.utils import secure_filename
from wtforms.fields import URLField
from flask_wtf.file import FileAllowed
from flask_wtf.file import FileRequired

app = Flask(__name__,
template_folder='./templates',
static_folder='./static')


bootstrap = Bootstrap(app)

class KeyForm(FlaskForm):
    key = FileField(validators=[
        FileRequired(),
        FileAllowed(['pem'], "Debe seleccionar un archivo .pem")
    ])
    submit = SubmitField('Cargar Fichero')

@app.route('/', methods=['GET', 'POST'])
def index():
    key_form = KeyForm()
    data = {}
    context = {
        'key_form':key_form,
        'data': data
    }
    if key_form.validate_on_submit():
        file = key_form.key.data
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),secure_filename(file.filename)))
        if file:
            try:
                key = RSA.importKey(open('./'+file.filename).read())
            except Exception:
                flash("No es una llave válida")
                return redirect('/')
            if key.has_private():
                data.update({
                    'type': 'private',
                    'modulus': key.n,
                    'publicExponent': key.e,
                    'privateExponent': key.d,
                    'prime1': key.p,
                    'prime2': key.q,
                    'exponent1': key._dp,
                    'exponent2': key._dq,
                    'coefficient': key.u,
                })
                context['data'] = data
                print("privada")
            else:
                data.update({
                    'type': 'public',
                    'modulus': key.n,
                    'publicExponent': key.e,
                })
                context['data'] = data
    return render_template('index.html', **context)

if __name__=='__main__':
    app.config['WTF_CSRF_ENABLED']= False
    app.config['SECRET_KEY']='KEY_SECRET'
    app.config['ENV']='development'
    app.run(debug=True)